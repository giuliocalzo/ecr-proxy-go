package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/giuliocalzolari/ecr-proxy/internal/logx"
	"github.com/giuliocalzolari/ecr-proxy/internal/tls"
	"github.com/giuliocalzolari/ecr-proxy/internal/token"
	"github.com/giuliocalzolari/ecr-proxy/internal/utils"
	"github.com/sethvargo/go-envconfig"
)

const (
	defaultPort       = "5000"
	tokenRefreshAfter = 6 * time.Hour
	v2Path            = "/v2/"
)

type config struct {
	Region      string `env:"AWS_REGION, default=us-east-1"`
	Account     string `env:"AWS_ACCOUNT_ID"`
	IpWhitelist string `env:"IP_WHITELIST, default="`
	TlsCertFile string `env:"TLS_CERT_FILE, default=./certs/tls.crt"`
	TlsKeyFile  string `env:"TLS_KEY_FILE, default=./certs/tls.key"`
	Port        string `env:"PORT, default=5000"`
}

type proxyServer struct {
	token       *token.Token
	tokenMux    sync.RWMutex
	cfg         config
	proxy       *httputil.ReverseProxy
	httpServer  *http.Server
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg, err := loadConfig(ctx)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	if err := validateConfig(cfg); err != nil {
		log.Fatalf("Invalid configuration: %v", err)
	}

	t, err := initializeToken(cfg)
	if err != nil {
		log.Fatalf("Failed to initialize token: %v", err)
	}

	server := &proxyServer{
		token: t,
		cfg:   cfg,
	}

	if err := server.setupProxy(); err != nil {
		log.Fatalf("Failed to setup proxy: %v", err)
	}

	if err := ensureTLSCertificates(cfg); err != nil {
		log.Fatalf("Failed to setup TLS certificates: %v", err)
	}

	server.setupRoutes()

	go server.refreshTokenPeriodically(ctx)

	server.httpServer = &http.Server{
		Addr:         ":" + cfg.Port,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		log.Printf("Starting HTTPS ECR proxy on port %s for %s", cfg.Port, t.GetEndpoint())
		if err := server.httpServer.ListenAndServeTLS(cfg.TlsCertFile, cfg.TlsKeyFile); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed: %v", err)
		}
	}()

	handleGracefulShutdown(ctx, cancel, server.httpServer)
}

func loadConfig(ctx context.Context) (config, error) {
	var cfg config
	if err := envconfig.Process(ctx, &cfg); err != nil {
		return cfg, err
	}

	if cfg.Account == "" {
		accountID, err := getAWSAccountID(cfg.Region)
		if err != nil {
			return cfg, fmt.Errorf("AWS_ACCOUNT_ID environment variable is required and could not be determined via STS: %w", err)
		}
		cfg.Account = accountID
		log.Printf("AWS_ACCOUNT_ID not set, using value from STS: %s", cfg.Account)
	}

	return cfg, nil
}

func validateConfig(cfg config) error {
	port, err := strconv.Atoi(cfg.Port)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("invalid port number: %s", cfg.Port)
	}
	return nil
}

func getAWSAccountID(region string) (string, error) {
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(region),
	})
	if err != nil {
		return "", err
	}
	stsSvc := sts.New(sess)
	idResp, err := stsSvc.GetCallerIdentity(&sts.GetCallerIdentityInput{})
	if err != nil || idResp.Account == nil {
		return "", err
	}
	return *idResp.Account, nil
}

func initializeToken(cfg config) (*token.Token, error) {
	t := token.NewToken(cfg.Region, cfg.Account)
	if !t.IsValid() {
		return nil, fmt.Errorf("failed to initialize valid ECR token")
	}
	return t, nil
}

func (s *proxyServer) setupProxy() error {
	target, err := url.Parse("https://" + s.token.GetEndpoint())
	if err != nil {
		return fmt.Errorf("failed to parse target URL: %w", err)
	}

	s.proxy = httputil.NewSingleHostReverseProxy(target)
	s.proxy.Director = func(req *http.Request) {
		s.tokenMux.RLock()
		endpoint := s.token.GetEndpoint()
		authToken := s.token.GetToken()
		s.tokenMux.RUnlock()

		req.URL.Scheme = "https"
		req.URL.Host = endpoint
		req.Host = endpoint
		req.Header.Set("Authorization", "Basic "+authToken)
	}

	return nil
}

func ensureTLSCertificates(cfg config) error {
	if _, err := os.Stat(cfg.TlsCertFile); os.IsNotExist(err) {
		log.Printf("TLS certificate not found, generating self-signed certificate at %s", cfg.TlsCertFile)
		if err := os.MkdirAll("./certs", 0700); err != nil {
			return fmt.Errorf("failed to create certs directory: %w", err)
		}
		if err := tls.Generate(cfg.TlsCertFile, cfg.TlsKeyFile); err != nil {
			return fmt.Errorf("failed to generate TLS certificates: %w", err)
		}
		log.Printf("WARNING: Using self-signed certificate. Clients must trust this certificate.")
	}
	return nil
}

func (s *proxyServer) setupRoutes() {
	http.HandleFunc(v2Path, s.handleProxy)
	http.HandleFunc("/healthz", s.handleHealthz)
	http.HandleFunc("/readyz", s.handleReadyz)
}

func (s *proxyServer) handleProxy(w http.ResponseWriter, r *http.Request) {
	if s.cfg.IpWhitelist != "" {
		clientIP := utils.GetClientIP(r)
		allowed := utils.IsIPAllowed(clientIP, s.cfg.IpWhitelist)
		if !allowed {
			logx.Print(r, "Denied request from IP (not in whitelist)")
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
	}

	if r.URL.Path != v2Path {
		logx.Print(r, "proxy to ECR")
	}

	s.proxy.ServeHTTP(w, r)
}

func (s *proxyServer) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func (s *proxyServer) handleReadyz(w http.ResponseWriter, r *http.Request) {
	s.tokenMux.RLock()
	valid := s.token.IsValid()
	s.tokenMux.RUnlock()

	if valid {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("ECR token is not valid or expired"))
	}
}

func (s *proxyServer) refreshTokenPeriodically(ctx context.Context) {
	ticker := time.NewTicker(tokenRefreshAfter)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			log.Println("Refreshing ECR token...")
			newToken := token.NewToken(s.cfg.Region, s.cfg.Account)
			if newToken.IsValid() {
				s.tokenMux.Lock()
				s.token = newToken
				s.tokenMux.Unlock()
				log.Println("ECR token refreshed successfully")
			} else {
				log.Println("Failed to refresh ECR token")
			}
		}
	}
}

func handleGracefulShutdown(ctx context.Context, cancel context.CancelFunc, server *http.Server) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	<-sigChan
	log.Println("Shutdown signal received, gracefully stopping server...")

	cancel()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("Server shutdown error: %v", err)
	} else {
		log.Println("Server stopped gracefully")
	}
}