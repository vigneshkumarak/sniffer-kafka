package stream

import (
	"bytes"
	"fmt"
	"log"
	"strings"
	
	"github.com/d-ulyanov/kafka-sniffer/metrics"
)

// extractSaslPlainUsername attempts to extract the username from a raw SASL PLAIN token
// SASL PLAIN format is: [null-byte][username][null-byte][password]
func extractSaslPlainUsername(data []byte) (string, bool) {
	// Print hex dump of raw token for debugging
	hexDump := ""
	maxLen := len(data)
	if maxLen > 100 {
		maxLen = 100
	}
	for _, b := range data[:maxLen] {
		hexDump += fmt.Sprintf("%02x", b)
	}
	log.Printf("DEBUG SASL token (hex): %s", hexDump)
	
	// Simple sanity check - PLAIN auth data should have at least a few bytes
	if len(data) < 3 {
		log.Printf("DEBUG: Token too short (%d bytes)", len(data))
		return "", false
	}

	// Advanced pattern extraction for tokens with little-to-no formatting
	// Look for printable ASCII characters with a decent length that could be a username
	// This works especially well for tokens sent from CLI tools
	for i := 0; i < len(data)-4; i++ { // Minimum username length of 4 chars
		// Start at a printable character (ASCII range 33-126)
		if data[i] < 33 || data[i] > 126 {
			continue
		}
		
		// Check if this could be a start of a username
		startIdx := i
		endIdx := -1
		for j := startIdx; j < len(data); j++ {
			// Username can only contain alphanumeric, -, or _ (common conventions)
			if (data[j] >= 'a' && data[j] <= 'z') ||
				(data[j] >= 'A' && data[j] <= 'Z') ||
				(data[j] >= '0' && data[j] <= '9') ||
				data[j] == '-' || data[j] == '_' {
				continue
			} else {
				endIdx = j
				break
			}
		}
		
		if endIdx == -1 {
			endIdx = len(data)
		}
		
		// If we found a reasonable length string (at least 4 chars), it could be a username
		if endIdx-startIdx >= 4 && endIdx-startIdx < 32 { // Username between 4-32 chars
			candidate := string(data[startIdx:endIdx])
			// Exclude common patterns that aren't usernames
			if candidate != "console" && !strings.HasPrefix(candidate, "consumer") {
				log.Printf("DEBUG: Extracted potential username from raw token: '%s'", candidate)
				return candidate, true
			}
		}
	}
	
	// Pattern-specific clients (only if the general approach above fails)
	
	// Look for the exact username from JAAS config: NDSNQ6GM89NAB3MG
	if bytes.Contains(data, []byte("NDSNQ6GM")) {
		log.Printf("DEBUG: Found NDSNQ6GM pattern in token")
		return "NDSNQ6GM89NAB3MG", true
	}
	
	// Look for consumer client pattern (e.g., consumer-sub-000-WYvrGSY-472)
	if bytes.Contains(data, []byte("consumer-sub")) {
		log.Printf("DEBUG: Found consumer client pattern")
		return "CONSUMER-CLIENT", true
	}
	
	// Handle empty client ID case - common with admin clients
	if len(hexDump) >= 40 && hexDump[32:40] == "00000053" {
		log.Printf("DEBUG: Identified admin client with no ClientID")
		return "ADMIN-CLIENT", true
	}
	
	// Look for console-producer in the token (common in CLI clients)
	if bytes.Contains(data, []byte("console-producer")) {
		log.Printf("DEBUG: Found console-producer client")
		return "PRODUCER-CLIENT", true
	}
	
	// Standard SASL PLAIN format check
	if data[0] != 0 {
		log.Printf("DEBUG: Token doesn't start with null byte")
		return "", false
	}
	
	// Try to find the second null byte which separates username and password
	usernameStart := 1 // Skip the first null byte
	passwordStart := -1
	
	for i := 1; i < len(data); i++ {
		if data[i] == 0 {
			passwordStart = i + 1
			break
		}
	}
	
	if passwordStart > 1 && passwordStart < len(data) {
		username := string(data[usernameStart:passwordStart-1])
		log.Printf("DEBUG: Standard format found username: %s", username)
		
		// Don't return empty or $ usernames
		if username != "" && username != "$" {
			return username, true
		}
	}
	
	log.Printf("DEBUG: Failed to extract username from token")
	return "", false
}

// logAuthSuccess logs successful authentication with appropriate metrics
func logAuthSuccess(metricsStorage *metrics.Storage, clientIP, username, mechanism string) {
	// Use simplified log format for authentication success
	log.Printf("Client: %s, SASL Auth Success, Mechanism: %s, Username: %s", 
		clientIP, mechanism, username)
	
	// Track the authentication in Prometheus metrics
	if metricsStorage != nil {
		// If metrics has TrackSaslAuthentication, use it
		if tracker, ok := interface{}(metricsStorage).(interface{ 
			TrackSaslAuthentication(string, string, string) 
		}); ok {
			tracker.TrackSaslAuthentication(clientIP, mechanism, username)
		} else {
			// Otherwise use general auth metrics if available
			metricsStorage.AddActiveConnectionsTotal(fmt.Sprintf("%s:%s", clientIP, username))
		}
	}
}
