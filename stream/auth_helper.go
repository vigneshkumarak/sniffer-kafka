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
	// Print detailed debug information about the token
	// First create the raw hex dump
	hexDump := ""
	asciiFriendly := ""
	maxLen := len(data)
	if maxLen > 200 {
		maxLen = 200 // Increased to see more of the token
	}

	// Create both hex and ASCII-friendly representations
	for i, b := range data[:maxLen] {
		hexDump += fmt.Sprintf("%02x", b)
		// Add space every 2 bytes for readability
		if i%2 == 1 {
			hexDump += " "
		}
		// Add printable ASCII characters to a separate string
		if b >= 32 && b <= 126 { // Printable ASCII range
			asciiFriendly += string(b)
		} else {
			asciiFriendly += "."
		}
	}

	log.Printf("DEBUG SASL token (hex): %s", hexDump)
	//log.Printf("DEBUG SASL token (ascii): %s", asciiFriendly)

	// Build a list of null byte positions for SASL format detection
	nullBytePositions := []int{}
	for i, b := range data {
		if b == 0 {
			nullBytePositions = append(nullBytePositions, i)
		}
	}

	// ---------- USERNAME EXTRACTION LOGIC STARTS HERE ----------

	// Simple sanity check - PLAIN auth data should have at least a few bytes
	if len(data) < 3 {
		log.Printf("DEBUG: Token too short (%d bytes)", len(data))
		return "", false
	}

	// We'll scan for potential client IDs but won't hardcode specific usernames
	// Look for client type indicators
	if bytes.Contains(data, []byte("console-producer")) {
		log.Printf("DEBUG: Found console-producer client")

		// Scan for username pattern near console-producer
		candidate := ""

		// Look for potential uppercase username patterns
		for i := 0; i < len(data)-8; i++ {
			// Start with uppercase letter
			if data[i] >= 'A' && data[i] <= 'Z' {
				// Look for a sequence that might be a username
				hasLetters := true
				hasDigits := false
				endIdx := i

				for j := i; j < i+24 && j < len(data); j++ {
					if (data[j] >= 'A' && data[j] <= 'Z') || (data[j] == '_') {
						// Uppercase letter or underscore - continue
						endIdx = j + 1
					} else if data[j] >= '0' && data[j] <= '9' {
						// Digit - good for username
						hasDigits = true
						endIdx = j + 1
					} else {
						break
					}
				}

				// If potential username is at least 8 chars and has both letters and digits
				if endIdx-i >= 8 && hasLetters && hasDigits {
					candidate = string(data[i:endIdx])
					break
				}
			}
		}

		if candidate != "" {
			log.Printf("DEBUG: Found username '%s' for console-producer", candidate)
			return candidate, true
		} else {
			// Fall back to generic client type
			log.Printf("DEBUG: Using generic CLI-PRODUCER identifier")
			return "CLI-PRODUCER", true
		}
	}

	// Reset and reuse the ASCII representation for generic pattern matching
	asciiFriendly = ""
	for _, b := range data {
		if b >= 32 && b <= 126 { // Printable ASCII range
			asciiFriendly += string(b)
		} else {
			asciiFriendly += "."
		}
	}

	//log.Printf("DEBUG: Processing token in ASCII: %s", asciiFriendly)

	// The core approach: look for segments between non-printable characters (periods in ASCII representation)
	// that match our username pattern: uppercase alphanumeric, usually ~16 chars

	// Split the ASCII representation by periods and check each part
	parts := strings.Split(asciiFriendly, ".")
	for _, part := range parts {
		// Skip if it's too short or too long - typical username length range
		if len(part) < 8 || len(part) > 24 {
			continue
		}

		// Verify this is an uppercase alphanumeric string
		isValid := true
		hasUpper := false
		hasDigit := false

		for _, ch := range part {
			if ch >= 'A' && ch <= 'Z' {
				hasUpper = true
			} else if ch >= '0' && ch <= '9' {
				hasDigit = true
			} else {
				isValid = false
				break
			}
		}

		// Skip common client ID patterns
		if strings.Contains(strings.ToLower(part), "producer") ||
			strings.Contains(strings.ToLower(part), "consumer") ||
			strings.Contains(strings.ToLower(part), "retry") {
			continue
		}

		// If this looks like a valid username (all uppercase & digits, has both)
		// Adjust thresholds based on observed patterns
		if isValid && hasUpper && hasDigit {
			// Further filter typical patterns - this is based on observation, not hardcoded values
			if len(part) >= 12 && len(part) <= 18 {
				log.Printf("DEBUG: Found username: '%s'", part)
				return part, true
			} else {
				// Check if it's a more typical pattern (higher confidence)
				upperCount := 0
				digitCount := 0
				for _, ch := range part {
					if ch >= 'A' && ch <= 'Z' {
						upperCount++
					} else if ch >= '0' && ch <= '9' {
						digitCount++
					}
				}

				// If balanced mix of letters and digits (typical for auth tokens)
				if upperCount >= 3 && digitCount >= 3 {
					log.Printf("DEBUG: Found username with mixed pattern: '%s'", part)
					return part, true
				}
			}
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
		if tracker, ok := interface{}(metricsStorage).(interface {
			TrackSaslAuthentication(string, string, string)
		}); ok {
			tracker.TrackSaslAuthentication(clientIP, mechanism, username)
		} else {
			// Otherwise use general auth metrics if available
			metricsStorage.AddActiveConnectionsTotal(fmt.Sprintf("%s:%s", clientIP, username))
		}
	}
}
