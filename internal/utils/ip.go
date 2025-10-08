package utils

import (
	"log"
	"net"
	"strings"
)

// IsIPAllowed checks if the given remoteAddr IP is allowed based on the ipWhitelist.
// remoteAddr should be in the format "IP:port" or just "IP".
// ipWhitelist is a comma-separated list of IPs or CIDR ranges.
// Returns true if the IP is in the whitelist, false otherwise.
func IsIPAllowed(remoteAddr, ipWhitelist string) bool {
	// Handle empty whitelist - deny all by default
	if strings.TrimSpace(ipWhitelist) == "" {
		log.Printf("Empty whitelist - denying access")
		return false
	}

	// Split the whitelist into individual CIDRs or IPs
	whitelist := strings.Split(ipWhitelist, ",")
	var ipNets []*net.IPNet

	for _, entry := range whitelist {
		entry = strings.TrimSpace(entry)
		// Remove spaces around / in CIDR notation
		entry = strings.ReplaceAll(entry, " ", "")
		if entry == "" {
			continue
		}
		// If entry is a plain IP, convert to /32 or /128 CIDR
		if !strings.Contains(entry, "/") {
			if strings.Contains(entry, ":") {
				entry += "/128"
			} else {
				entry += "/32"
			}
		}
		_, ipnet, err := net.ParseCIDR(entry)
		if err != nil {
			log.Printf("Warning: invalid whitelist entry '%s': %v", entry, err)
			continue
		}
		ipNets = append(ipNets, ipnet)
	}

	// Extract the IP from the remote address using SplitHostPort
	ipStr := remoteAddr
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		// Might be IP without port, try parsing directly
		host = strings.TrimSpace(remoteAddr)
	}
	
	ip := net.ParseIP(strings.TrimSpace(host))
	if ip == nil {
		log.Printf("Failed to parse IP from remoteAddr: %s", remoteAddr)
		return false
	}

	// Normalize IPv4-mapped IPv6 addresses to IPv4
	if ip.To4() != nil {
		ip = ip.To4()
	}

	// Check if the IP is in any of the allowed subnets
	for _, ipnet := range ipNets {
		if ipnet.Contains(ip) {
			return true
		}
	}

	log.Printf("Access denied for IP (not in whitelist)")
	return false
}