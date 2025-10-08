package token

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ecr"
)

const (
	tokenRefreshAfter = 6 * time.Hour // ECR tokens are valid for 12 hours
)

type Token struct {
	Token     string
	ExpiresAt time.Time
	Endpoint  string // ECR endpoint, e.g., "123456789012.dkr.ecr.us-east-1.amazonaws.com"
	Region    string
	Account   string
	Lock      sync.RWMutex
	sess      *session.Session
}

// NewToken creates a new Token instance with the provided token string and expiry time.
func NewToken(region, account string) (*Token, error) {
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(region),
	})
	if err != nil {
		return nil, err
	}

	t := &Token{
		Region:  region,
		Account: account,
		sess:    sess,
	}
	if err := t.Refresh(); err != nil {
		return nil, err
	}
	return t, nil
}

// IsValid checks if the token is still valid based on the current time.
func (t *Token) IsValid() bool {
	t.Lock.RLock()
	defer t.Lock.RUnlock()
	return time.Now().Before(t.ExpiresAt) && len(t.Token) > 0
}

// GetToken returns the token string.
func (t *Token) GetToken() (string, error) {
	if t.isExpiredUnsafe() {
		if err := t.Refresh(); err != nil {
			return "", err
		}
	}
	t.Lock.RLock()
	defer t.Lock.RUnlock()
	return t.Token, nil
}

// GetEndpoint returns the ECR endpoint associated with the token.
func (t *Token) GetEndpoint() string {
	t.Lock.RLock()
	defer t.Lock.RUnlock()
	return t.Endpoint
}

// GetExpiresAt returns the expiry time of the token.
func (t *Token) GetExpiresAt() time.Time {
	t.Lock.RLock()
	defer t.Lock.RUnlock()
	return t.ExpiresAt
}

// IsExpired checks if the token has expired.
func (t *Token) IsExpired() bool {
	t.Lock.RLock()
	defer t.Lock.RUnlock()
	return time.Now().After(t.ExpiresAt)
}

// isExpiredUnsafe checks if the token has expired without locking (internal use).
func (t *Token) isExpiredUnsafe() bool {
	t.Lock.RLock()
	defer t.Lock.RUnlock()
	return time.Now().After(t.ExpiresAt)
}

func (t *Token) Refresh() error {
	t.Lock.Lock()
	defer t.Lock.Unlock()

	// Double-check: verify token still needs refresh after acquiring lock
	if time.Now().Before(t.ExpiresAt) && len(t.Token) > 0 {
		return nil
	}

	// Get ECR authorization token
	svc := ecr.New(t.sess)
	result, err := svc.GetAuthorizationToken(&ecr.GetAuthorizationTokenInput{
		RegistryIds: []*string{aws.String(t.Account)},
	})
	if err != nil {
		return err
	}

	if len(result.AuthorizationData) == 0 {
		return fmt.Errorf("no authorization data returned from ECR")
	}

	authData := result.AuthorizationData[0]
	if authData == nil {
		return fmt.Errorf("authorization data is nil")
	}
	if authData.AuthorizationToken == nil {
		return fmt.Errorf("authorization token is nil")
	}
	if authData.ExpiresAt == nil {
		return fmt.Errorf("expiration time is nil")
	}
	if authData.ProxyEndpoint == nil {
		return fmt.Errorf("proxy endpoint is nil")
	}

	// Update our token and expiry
	t.Token = *authData.AuthorizationToken
	t.ExpiresAt = authData.ExpiresAt.Add(-tokenRefreshAfter)
	endpoint := *authData.ProxyEndpoint
	if strings.HasPrefix(endpoint, "https://") {
		endpoint = endpoint[8:]
	}
	t.Endpoint = endpoint
	return nil
}