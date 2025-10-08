package utils

import (
	"testing"
)

// TestIsIPAllowed verifies IP whitelist matching for both IPv4 and IPv6 addresses
// with support for exact IPs, CIDR notation, and comma-separated lists.
func TestIsIPAllowed(t *testing.T) {
	tests := []struct {
		name        string
		remoteAddr  string
		ipWhitelist string
		want        bool
	}{
		{
			name:        "should allow IPv4 exact match",
			remoteAddr:  "192.168.1.10:12345",
			ipWhitelist: "192.168.1.10",
			want:        true,
		},
		{
			name:        "should allow IPv4 in CIDR range",
			remoteAddr:  "10.0.0.5:54321",
			ipWhitelist: "10.0.0.0/8",
			want:        true,
		},
		{
			name:        "should deny IPv4 not in CIDR range",
			remoteAddr:  "172.16.0.1:80",
			ipWhitelist: "192.168.0.0/16",
			want:        false,
		},
		{
			name:        "should allow IPv6 exact match",
			remoteAddr:  "[2001:db8::1]:443",
			ipWhitelist: "2001:db8::1",
			want:        true,
		},
		{
			name:        "should allow IPv6 in CIDR range",
			remoteAddr:  "[2001:db8::2]:443",
			ipWhitelist: "2001:db8::/32",
			want:        true,
		},
		{
			name:        "should deny IPv6 not in CIDR range",
			remoteAddr:  "[2001:db9::1]:443",
			ipWhitelist: "2001:db8::/32",
			want:        false,
		},
		{
			name:        "should allow when matching second entry in list",
			remoteAddr:  "10.1.2.3:8080",
			ipWhitelist: "192.168.1.1,10.0.0.0/8",
			want:        true,
		},
		{
			name:        "should deny when matching no entries in list",
			remoteAddr:  "8.8.8.8:53",
			ipWhitelist: "192.168.1.1,10.0.0.0/8",
			want:        false,
		},
		{
			name:        "should allow IPv4 without port",
			remoteAddr:  "127.0.0.1",
			ipWhitelist: "127.0.0.1",
			want:        true,
		},
		{
			name:        "should deny when whitelist is empty",
			remoteAddr:  "127.0.0.1:1234",
			ipWhitelist: "",
			want:        false,
		},
		{
			name:        "should deny malformed remoteAddr",
			remoteAddr:  "not_an_ip",
			ipWhitelist: "127.0.0.1",
			want:        false,
		},
		{
			name:        "should deny malformed whitelist entries",
			remoteAddr:  "127.0.0.1:1234",
			ipWhitelist: "bad_cidr",
			want:        false,
		},
		{
			name:        "should allow IPv4-mapped IPv6 address",
			remoteAddr:  "[::ffff:192.168.1.10]:8080",
			ipWhitelist: "192.168.1.10",
			want:        true,
		},
		{
			name:        "should allow localhost IPv6",
			remoteAddr:  "[::1]:8080",
			ipWhitelist: "::1",
			want:        true,
		},
		{
			name:        "should handle whitespace in whitelist",
			remoteAddr:  "192.168.1.10:8080",
			ipWhitelist: " 192.168.1.10 , 10.0.0.0/8 ",
			want:        true,
		},
		{
			name:        "should allow with /32 CIDR (single IP)",
			remoteAddr:  "192.168.1.10:8080",
			ipWhitelist: "192.168.1.10/32",
			want:        true,
		},
		{
			name:        "should deny with /32 CIDR mismatch",
			remoteAddr:  "192.168.1.11:8080",
			ipWhitelist: "192.168.1.10/32",
			want:        false,
		},
		{
			name:        "should allow with /0 CIDR (match all IPv4)",
			remoteAddr:  "8.8.8.8:53",
			ipWhitelist: "0.0.0.0/0",
			want:        true,
		},
		{
			name:        "should allow with ::/0 CIDR (match all IPv6)",
			remoteAddr:  "[2001:db8::1]:443",
			ipWhitelist: "::/0",
			want:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsIPAllowed(tt.remoteAddr, tt.ipWhitelist)
			if got != tt.want {
				t.Errorf("IsIPAllowed(%q, %q) = %v; want %v", tt.remoteAddr, tt.ipWhitelist, got, tt.want)
			}
		})
	}
}

func BenchmarkIsIPAllowed(b *testing.B) {
	testCases := []struct {
		name        string
		remoteAddr  string
		ipWhitelist string
	}{
		{"IPv4 exact", "192.168.1.10:12345", "192.168.1.10"},
		{"IPv4 CIDR", "10.0.0.5:54321", "10.0.0.0/8"},
		{"IPv6 CIDR", "[2001:db8::2]:443", "2001:db8::/32"},
		{"Multiple entries", "10.1.2.3:8080", "192.168.1.1,10.0.0.0/8,172.16.0.0/12"},
	}

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				IsIPAllowed(tc.remoteAddr, tc.ipWhitelist)
			}
		})
	}
}