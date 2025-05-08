package kafka

import (
	"fmt"

	"github.com/d-ulyanov/kafka-sniffer/metrics"
)

// SaslHandshakeRequest is the first step in SASL authentication
// It's used by clients to determine which SASL mechanisms are supported by the broker
//
// API key: 17
// Min Version: 0
// Max Version: 1
type SaslHandshakeRequest struct {
	// Version of the API
	ApiVersion int16
	
	// SASL mechanism name requested by the client
	Mechanism string
	
	// Additional fields for tracking client authentication
	ClientAddr string // Set during CollectClientMetrics
	Username   string // May be populated during subsequent traffic analysis
}

// Decode deserializes the SaslHandshakeRequest from binary data
func (r *SaslHandshakeRequest) Decode(pd PacketDecoder, version int16) error {
	// Store the API version
	r.ApiVersion = version
	
	// Get the mechanism name (string)
	mechanism, err := pd.getString()
	if err != nil {
		return err
	}
	
	r.Mechanism = mechanism
	return nil
}

// key returns the API key for SaslHandshake requests (17)
func (r *SaslHandshakeRequest) key() int16 {
	return 17
}

// version returns the version of this request
func (r *SaslHandshakeRequest) version() int16 {
	return r.ApiVersion
}

// requiredVersion returns the minimum required version for this protocol
func (r *SaslHandshakeRequest) requiredVersion() Version {
	return MinVersion
}

// CollectClientMetrics collects Kafka-related metrics about the connection
func (r *SaslHandshakeRequest) CollectClientMetrics(clientAddr string) {
	// Store client address for later correlation
	r.ClientAddr = clientAddr
	
	// Include API version in metrics
	versionStr := fmt.Sprintf("%d", r.ApiVersion)
	metrics.RequestsCount.WithLabelValues(clientAddr, "sasl_handshake", versionStr).Inc()
	
	// Log the SASL handshake attempt with mechanism
	fmt.Printf("[SASL HANDSHAKE] Client %s requested authentication using mechanism: %s\n", 
		clientAddr, r.Mechanism)
	
	// Track SASL mechanism in authentication metrics
	if r.Mechanism != "" {
		// Note: Username will be captured later from the SaslAuthenticate request or raw SASL token
		// For now, we just track the mechanism with an empty username
		metrics.AuthenticationInfo.WithLabelValues(clientAddr, r.Mechanism, "").Inc()
		
		// Store this handshake in a global map for correlation with future packets
		StoreAuthHandshake(clientAddr, r.Mechanism)
	}
}

// String implements fmt.Stringer interface
func (r *SaslHandshakeRequest) String() string {
	return fmt.Sprintf("SaslHandshake(Mechanism=%s)", r.Mechanism)
}