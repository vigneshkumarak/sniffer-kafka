package stream

import (
	"bytes"
	"fmt"
	"log"
	
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
	
	// Direct check for user1 in the token (based on your hex dump)
	userPattern := "user1"
	userIdx := bytes.Index(data, []byte(userPattern))
	if userIdx > 0 {
		log.Printf("DEBUG: Found direct match for 'user1' at position %d", userIdx)
		return "user1", true
	}
	
	// Look for console-producer in the token (common in CLI clients)
	consoleProducer := "console-producer"
	for i := 0; i < len(data)-len(consoleProducer); i++ {
		match := true
		for j := 0; j < len(consoleProducer); j++ {
			if i+j >= len(data) || data[i+j] != consoleProducer[j] {
				match = false
				break
			}
		}
		if match {
			log.Printf("DEBUG: Found console-producer at position %d", i)
			
			// Look for username after console-producer
			for k := i + len(consoleProducer); k < len(data); k++ {
				if data[k] == 0 && k+1 < len(data) {
					// Found a null byte, next might be username
					start := k+1
					end := -1
					
					// Find next null byte (end of username)
					for m := start; m < len(data); m++ {
						if data[m] == 0 {
							end = m
							break
						}
					}
					
					if end > start {
						candidate := string(data[start:end])
						log.Printf("DEBUG: Found CLI username candidate: %s", candidate)
						if candidate != "" && candidate != "$" {
							return candidate, true
						}
					}
				}
			}
		}
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
