package kafka

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// AuthSession tracks SASL authentication sessions
type AuthSession struct {
	ClientAddr string
	Mechanism  string
	Username   string
	Timestamp  time.Time
}

var (
	// Global auth session tracker
	authSessions     = make(map[string]*AuthSession)
	// Track usernames by base IP (without port)
	ipToUsername     = make(map[string]string)
	authSessionsLock sync.RWMutex
)

// extractBaseIP extracts the base IP address from a "ip:port" string
func extractBaseIP(addr string) string {
	parts := strings.Split(addr, ":")
	if len(parts) > 0 {
		// If IPv6 address, handle differently
		if strings.Count(addr, ":") > 1 && (strings.HasPrefix(addr, "[") || !strings.Contains(addr, ".")) {
			// For IPv6, find the last colon if not surrounded by brackets
			if strings.HasPrefix(addr, "[") && strings.Contains(addr, "]") {
				parts := strings.Split(addr, "]")
				if len(parts) > 0 {
					return strings.TrimPrefix(parts[0], "[")
				}
			}
			// Just return the raw IPv6 address for now
			return addr
		}
		return parts[0] // Return just the IP part for IPv4
	}
	return addr
}

// StoreAuthHandshake records a SASL handshake for later correlation with authentication data
func StoreAuthHandshake(clientAddr, mechanism string) {
	authSessionsLock.Lock()
	defer authSessionsLock.Unlock()
	
	// Create a new auth session
	authSessions[clientAddr] = &AuthSession{
		ClientAddr: clientAddr,
		Mechanism:  mechanism,
		Timestamp:  time.Now(),
	}
	
	// Debug output is now removed
		
	// Clean up old sessions - keep map from growing unbounded
	cleanupOldSessions()
}

// UpdateAuthSession adds username information to an existing session
func UpdateAuthSession(clientAddr, username string) bool {
	authSessionsLock.Lock()
	defer authSessionsLock.Unlock()
	
	// Updating auth session with username
	
	session, exists := authSessions[clientAddr]
	if !exists {
		// Even if there's no session, still map the base IP to username
		baseIP := extractBaseIP(clientAddr)
		ipToUsername[baseIP] = username
		// No session found but still mapped base IP to username
		return true
	}
	
	// Update with username
	session.Username = username
	
	// Also store by base IP for easier lookup
	baseIP := extractBaseIP(clientAddr)
	ipToUsername[baseIP] = username
	
	// Log the complete authentication
	fmt.Printf("[AUTHENTICATION COMPLETE] Client %s authenticated as '%s' using mechanism '%s'\n",
		clientAddr, username, session.Mechanism)
	// Mapped base IP to username
	
	// Debug log the current state of ipToUsername map
	// Auth tracker username mappings initialized
		
	return true
}

// GetAuthSession retrieves auth session information for a client
func GetAuthSession(clientAddr string) (*AuthSession, bool) {
	authSessionsLock.RLock()
	defer authSessionsLock.RUnlock()
	
	// First try exact match
	session, exists := authSessions[clientAddr]
	if exists {
		// Found exact session match
		return session, true
	}
	
	// If not found, try matching by base IP
	baseIP := extractBaseIP(clientAddr)
	username, exists := ipToUsername[baseIP]
	if exists {
		// Found username for base IP
		
		// Create a synthetic session with the username
		return &AuthSession{
			ClientAddr: clientAddr,
			Username:   username,
			Timestamp:  time.Now(),
		}, true
	}
	
	// No session found
	return nil, false
}

// GetUsernameByIP gets a username using just the IP part of the address
func GetUsernameByIP(clientAddr string) string {
	authSessionsLock.RLock()
	defer authSessionsLock.RUnlock()
	
	// Extract base IP (no port)
	baseIP := extractBaseIP(clientAddr)
	
	// Debug log the current ipToUsername map
	// Looking up username by IP address
	
	// Try to find username by base IP
	if username, exists := ipToUsername[baseIP]; exists {
		// Found username for IP
		return username
	}
	
	// No username found for IP
	return ""
}

// cleanupOldSessions removes sessions older than 5 minutes
func cleanupOldSessions() {
	now := time.Now()
	for addr, session := range authSessions {
		if now.Sub(session.Timestamp) > 5*time.Minute {
			delete(authSessions, addr)
			// Don't clean up ipToUsername map - we want to keep these mappings longer
		}
	}
}
