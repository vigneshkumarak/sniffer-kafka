package stream

import (
	"fmt"
	"log"
	
	"github.com/d-ulyanov/kafka-sniffer/metrics"
)

// extractSaslPlainUsername attempts to extract the username from a raw SASL PLAIN token
// SASL PLAIN format is: [null-byte][username][null-byte][password]
func extractSaslPlainUsername(data []byte) (string, bool) {
	// Simple sanity check - PLAIN auth data should have at least a few bytes
	if len(data) < 3 {
		return "", false
	}
	
	// Check if this looks like PLAIN auth data (begins with null byte)
	if data[0] != 0 {
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
		return username, true
	}
	
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
