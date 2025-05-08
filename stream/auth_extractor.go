package stream

import (
	"bufio"
	"bytes"
	"log"
	"strings"
	
	"github.com/d-ulyanov/kafka-sniffer/kafka"
	"github.com/d-ulyanov/kafka-sniffer/metrics"
)

// tryExtractAuthData attempts to extract authentication information from
// raw buffer data that follows a SASL handshake
func (h *KafkaStream) tryExtractAuthData(buf *bufio.Reader, clientIP, mechanism string) {
	// Try to peek at a reasonable amount of data
	// Use inline conditional instead of min function to avoid Go 1.21 requirement
	peekSize := buf.Buffered()
	if peekSize > 1024 {
		peekSize = 1024 // Look at up to 1KB
	}
	if peekSize < 8 {
		// Not enough data to work with
		return
	}
	
	rawData, err := buf.Peek(peekSize)
	if err != nil {
		// Error peeking buffer
		return
	}
	
	// Examining bytes from client after handshake
	
	// Extract username using various methods based on mechanism
	var username string
	
	// PLAIN mechanism - look for null byte separators
	if strings.EqualFold(mechanism, "PLAIN") {
		username = extractPlainUsername(rawData)
	} else if strings.HasPrefix(strings.ToUpper(mechanism), "SCRAM-") {
		// SCRAM mechanism - look for n=username
		username = extractScramUsername(rawData)
	} else {
		// Try generic approaches
		username = extractGenericUsername(rawData)
	}
	
	// If we found a username, update authentication tracking
	if username != "" {
		log.Printf("[AUTHENTICATION] Extracted username '%s' from raw packet data for client %s",
			username, clientIP)
		
		// Store the username in our tracking system
		if kafka.UpdateAuthSession(clientIP, username) {
			// Now also update the metrics
			metrics.TrackSaslAuthentication(clientIP, mechanism, username)
		}
	}
}

// extractPlainUsername attempts to extract a username from PLAIN auth data
func extractPlainUsername(data []byte) string {
	// PLAIN format: [null-byte][username][null-byte][password]
	if len(data) < 3 || data[0] != 0 {
		return ""
	}
	
	// Find second null byte
	secondNull := -1
	for i := 1; i < len(data); i++ {
		if data[i] == 0 {
			secondNull = i
			break
		}
	}
	
	if secondNull > 1 {
		username := string(data[1:secondNull])
		if isValidUsername(username) {
			return username
		}
	}
	
	return ""
}

// extractScramUsername attempts to extract a username from SCRAM auth data
func extractScramUsername(data []byte) string {
	// Look for n=username in the data
	usernamePrefix := []byte("n=")
	idx := bytes.Index(data, usernamePrefix)
	
	if idx >= 0 && idx+2 < len(data) {
		// Found username prefix, find the end (comma or other separator)
		start := idx + 2
		end := -1
		
		for i := start; i < len(data); i++ {
			if data[i] == ',' || data[i] == 0 {
				end = i
				break
			}
		}
		
		if end > start {
			username := string(data[start:end])
			if isValidUsername(username) {
				return username
			}
		}
	}
	
	return ""
}

// extractGenericUsername looks for patterns that might be usernames
func extractGenericUsername(data []byte) string {
	// JWT check - look for {"sub":"username"} pattern
	subField := []byte(`"sub":"`)
	idx := bytes.Index(data, subField)
	
	if idx >= 0 && idx+7 < len(data) {
		start := idx + 7
		end := -1
		
		for i := start; i < len(data); i++ {
			if data[i] == '"' {
				end = i
				break
			}
		}
		
		if end > start {
			username := string(data[start:end])
			if isValidUsername(username) {
				return username
			}
		}
	}
	
	// Generic approach - look for sequences of printable characters
	// that might be usernames
	var candidate string
	inCandidate := false
	start := 0
	
	for i, b := range data {
		if isPrintable(b) {
			if !inCandidate {
				inCandidate = true
				start = i
			}
		} else if inCandidate {
			// End of candidate
			if i-start >= 3 {
				// Candidate must be at least 3 chars
				candidate = string(data[start:i])
				if isValidUsername(candidate) && !isCommonWord(candidate) {
					return candidate
				}
			}
			inCandidate = false
		}
	}
	
	// Check if we ended with a candidate in progress
	if inCandidate && len(data)-start >= 3 {
		candidate = string(data[start:])
		if isValidUsername(candidate) && !isCommonWord(candidate) {
			return candidate
		}
	}
	
	return ""
}

// isValidUsername checks if a string looks like a valid username
func isValidUsername(s string) bool {
	// Basic validation
	if len(s) < 3 || len(s) > 100 {
		return false
	}
	
	// Check if it contains reasonable characters
	for _, r := range s {
		if !((r >= 'a' && r <= 'z') || 
			 (r >= 'A' && r <= 'Z') || 
			 (r >= '0' && r <= '9') || 
			 r == '.' || r == '_' || r == '-' || r == '@') {
			return false
		}
	}
	
	return true
}

// isPrintable checks if a byte is in the printable ASCII range
func isPrintable(b byte) bool {
	return b >= 32 && b < 127
}

// isCommonWord checks if a string is a common word that might be a false positive
func isCommonWord(s string) bool {
	common := map[string]bool{
		"null": true, "true": true, "false": true, "yes": true, "no": true,
		"data": true, "json": true, "text": true, "type": true, "key": true,
		"value": true, "code": true, "name": true, "user": true, "token": true,
	}
	
	return common[strings.ToLower(s)]
}
