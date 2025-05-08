package kafka

import (
	"bytes"
	"encoding/base64"
	"fmt"
	
	"github.com/d-ulyanov/kafka-sniffer/metrics"
)

// SaslAuthenticateRequest is the request sent by clients to authenticate with a
// SASL-based mechanism. The sniffer can capture and decode this to extract
// authentication details such as usernames.
//
// API key: 36
// Min Version: 0
// Max Version: 2
type SaslAuthenticateRequest struct {
	// APIVersion is the version of SaslAuthenticate request
	ApiVersion int16

	// SASL authentication bytes (for PLAIN, this contains the username and password)
	SaslAuthBytes []byte
	
	// For PLAIN mechanism, these fields will be populated after decoding
	Username string
	Password string
	Mechanism string // The SASL mechanism being used (if we can determine it)
}

// Decode deserializes the SaslAuthenticateRequest from binary data
func (r *SaslAuthenticateRequest) Decode(pd PacketDecoder, version int16) error {
	// Store the version
	r.ApiVersion = version
	
	// Decode the SASL auth bytes
	authBytes, err := pd.getBytes()
	if err != nil {
		return err
	}
	
	r.SaslAuthBytes = authBytes
	
	// For PLAIN mechanism, the format is: [null-byte][username][null-byte][password]
	// Try to extract username and password if it looks like PLAIN format
	r.tryDecodePlainAuth(authBytes)
	
	return nil
}

// tryDecodePlainAuth attempts to extract username and password from PLAIN auth bytes
// The PLAIN mechanism format is: [null-byte][username][null-byte][password]
func (r *SaslAuthenticateRequest) tryDecodePlainAuth(authBytes []byte) {
	// Protect against panics in auth processing
	defer func() {
		if rec := recover(); rec != nil {
			// Reset values if we panic during decoding
			r.Username = ""
			r.Password = ""
		}
	}()

	// Simple sanity check - SASL auth data should have at least a few bytes
	if len(authBytes) < 3 {
		return
	}

	// We'll try multiple approaches to extract the username from various SASL mechanisms
	
	// =========================================================================================
	// Approach 1: Standard PLAIN auth format: [null-byte][username][null-byte][password]
	// =========================================================================================
	if len(authBytes) > 0 && authBytes[0] == 0 {
		// Try to find the second null byte which separates username and password
		usernameStart := 1 // Skip the first null byte
		passwordStart := -1
		
		for i := 1; i < len(authBytes); i++ {
			if authBytes[i] == 0 {
				passwordStart = i + 1
				break
			}
		}
		
		if passwordStart > 1 && passwordStart < len(authBytes) {
			r.Mechanism = "PLAIN"
			r.Username = string(authBytes[usernameStart:passwordStart-1])
			r.Password = string(authBytes[passwordStart:])
			
			// Redact password for security
			if len(r.Password) > 0 {
				r.Password = "******"
			}
			return
		}
	}
	
	// =========================================================================================
	// Approach 2: SCRAM-SHA-256/SCRAM-SHA-512 format
	// Client-first-message: gs2-header [n=username,r=client-nonce]
	// =========================================================================================
	for i := 0; i < len(authBytes)-2; i++ {
		// Look for the "n=" prefix that indicates username in SCRAM
		if i+2 <= len(authBytes) && authBytes[i] == 'n' && authBytes[i+1] == '=' {
			// Found the username indicator, find the end (next comma)
			userStart := i + 2
			userEnd := -1
			
			for j := userStart; j < len(authBytes); j++ {
				if authBytes[j] == ',' {
					userEnd = j
					break
				}
			}
			
			if userEnd > userStart {
				r.Mechanism = "SCRAM"
				r.Username = string(authBytes[userStart:userEnd])
				return
			}
		}
	}
	
	// =========================================================================================
	// Approach 3: JWT/OAUTHBEARER - look for "sub" claim in JWT payload
	// =========================================================================================
	// Check for JWT format: parts separated by periods
	jwtParts := bytes.Split(authBytes, []byte{'.'})
	if len(jwtParts) == 3 { // Header.Payload.Signature
		// Try to decode the payload (middle part)
		payload := jwtParts[1]
		
		// Base64 decode if possible
		decodedPayload, err := base64.RawURLEncoding.DecodeString(string(payload))
		if err == nil && len(decodedPayload) > 0 {
			// Look for "sub":"username" pattern in JSON
			subIndex := bytes.Index(decodedPayload, []byte(`"sub":"`)) 
			if subIndex >= 0 {
				subStart := subIndex + 7 // Length of "sub":"
				subEnd := -1
				
				// Find closing quote
				for i := subStart; i < len(decodedPayload); i++ {
					if decodedPayload[i] == '"' {
						subEnd = i
						break
					}
				}
				
				if subEnd > subStart {
					r.Mechanism = "JWT"
					r.Username = string(decodedPayload[subStart:subEnd])
					return
				}
			}
		}
	}
	
	// =========================================================================================
	// Approach 4: Generic approach - look for printable ASCII sequences that could be usernames
	// =========================================================================================
	start := -1
	end := -1
	
	// Find first printable character
	for i, b := range authBytes {
		if b >= 32 && b < 127 { // ASCII printable range
			start = i
			break
		}
	}
	
	// If we found a start, look for the end (null byte or non-printable)
	if start >= 0 {
		for i := start; i < len(authBytes); i++ {
			if authBytes[i] < 32 || authBytes[i] >= 127 {
				end = i
				break
			}
		}
		
		// If we didn't find an end, use the end of the array
		if end < 0 {
			end = len(authBytes)
		}
		
		// Extract what looks like a username if long enough
		if end - start >= 3 { // Reasonable minimum username length
			candidate := string(authBytes[start:end])
			
			// Simple validation - check if it looks like an email or username
			if len(candidate) <= 100 { // Sanity check on length
				r.Username = candidate
				r.Mechanism = "UNKNOWN"
			}
		}
	}
	
	// Log more details about auth bytes (for debugging only)
	if r.Username == "" && len(authBytes) > 0 {
		// We didn't extract a username but we have auth bytes
		// This might help with debugging by showing the first few bytes in hex
		previewLen := 16
		if len(authBytes) < previewLen {
			previewLen = len(authBytes)
		}
		hexPreview := fmt.Sprintf("%X", authBytes[:previewLen])
		fmt.Printf("[DEBUG] SASL auth bytes (no username extracted): %s\n", hexPreview)
	}
}

// key returns the API key for SaslAuthenticate requests (36)
func (r *SaslAuthenticateRequest) key() int16 {
	return 36
}

// version returns the version of this request
func (r *SaslAuthenticateRequest) version() int16 {
	return r.ApiVersion
}

// requiredVersion returns the minimum required version for this protocol
func (r *SaslAuthenticateRequest) requiredVersion() Version {
	return MinVersion
}

// CollectClientMetrics implements the ClientMetricsCollector interface
func (r *SaslAuthenticateRequest) CollectClientMetrics(clientAddr string) {
	versionStr := fmt.Sprintf("%d", r.ApiVersion)
	metrics.RequestsCount.WithLabelValues(clientAddr, "SaslAuthenticate", versionStr).Inc()
	
	// Always track the authentication attempt
	attemptUsername := r.Username
	if attemptUsername == "" {
		attemptUsername = "<unknown>"
	}
	
	// If we successfully extracted a username, track the authentication with full details
	if r.Username != "" {
		// Format auth details for consistent logging
		mechanism := r.Mechanism
		if mechanism == "" {
			mechanism = "UNKNOWN"
		}
		
		// Log a specific authentication success message
		fmt.Printf("[AUTHENTICATION] Client %s authenticated as user '%s' using mechanism '%s'\n", 
			clientAddr, r.Username, mechanism)
		
		// Track in metrics
		metrics.TrackSaslAuthentication(clientAddr, mechanism, r.Username)
	}
}

// String implements fmt.Stringer interface
func (r *SaslAuthenticateRequest) String() string {
	if r.Username != "" {
		return fmt.Sprintf("SaslAuthenticate(Username=%s, Mechanism=%s)", 
			r.Username, r.Mechanism)
	}
	return "SaslAuthenticate()"
}
