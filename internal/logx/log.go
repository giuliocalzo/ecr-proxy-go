package logx

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

type LogEntry struct {
	Method     string `json:"method"`
	SourceIP   string `json:"ip"`
	SourcePort string `json:"port"`
	Time       string `json:"time"`
	Msg        string `json:"msg"`
	Path       string `json:"path"`
}

func Print(r *http.Request, msg string) {
	// Extract client IP with X-Forwarded-For fallback
	clientIP := r.Header.Get("X-Forwarded-For")
	if clientIP != "" {
		// Take the first IP in the list and validate
		clientIP = strings.Split(clientIP, ",")[0]
		clientIP = strings.TrimSpace(clientIP)
		if net.ParseIP(clientIP) == nil {
			clientIP = ""
		}
	}
	if clientIP == "" {
		clientIP = r.Header.Get("X-Real-IP")
		if clientIP != "" && net.ParseIP(clientIP) == nil {
			clientIP = ""
		}
	}

	// Fallback to RemoteAddr
	remoteAddr := r.RemoteAddr
	host, port := "", ""
	if clientIP == "" {
		var err error
		host, port, err = net.SplitHostPort(remoteAddr)
		if err != nil {
			host = remoteAddr
			port = ""
			// Remove IPv6 brackets if present
			host = strings.Trim(host, "[]")
		}
	} else {
		host = clientIP
		_, port, _ = net.SplitHostPort(remoteAddr)
	}

	// Sanitize msg to prevent log injection
	sanitizedMsg := strings.ReplaceAll(msg, "\n", "\\n")
	sanitizedMsg = strings.ReplaceAll(sanitizedMsg, "\r", "\\r")

	logEntry := LogEntry{
		Method:     r.Method,
		SourceIP:   host,
		SourcePort: port,
		Time:       time.Now().Format(time.RFC3339),
		Msg:        sanitizedMsg,
		Path:       r.URL.Path,
	}

	logData, err := json.Marshal(logEntry)
	if err != nil {
		fmt.Printf("Error marshaling log entry: %v\n", err)
		return
	}

	fmt.Printf("%s\n", logData)
}