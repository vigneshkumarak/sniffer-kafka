package kafka

import (
	"fmt"
	"github.com/d-ulyanov/kafka-sniffer/metrics"
)

// GenericRequest implements the ProtocolBody interface for Kafka APIs that don't have
// full decoder implementations. It captures the key API details for reporting.
type GenericRequest struct {
	ApiKey      int16
	ApiName     string
	Version     int16
	ClientID    string // For client tracking
	Topic       string // Optionally track a topic if it's in the message
	RawBytes    []byte
}

// Key returns the Kafka protocol key for this request
func (r *GenericRequest) key() int16 {
	return r.ApiKey
}

// Version returns the Kafka protocol version for this request
func (r *GenericRequest) version() int16 {
	if r.Version != 0 {
		return r.Version
	}
	return 0
}

// requiredVersion returns the minimum protocol version required for this message
func (r *GenericRequest) requiredVersion() Version {
	return MinVersion
}

// CollectClientMetrics implements the ProtocolBody interface for metrics collection
func (r *GenericRequest) CollectClientMetrics(clientAddr string) {
	// Track this as a generic API call with version information
	versionStr := fmt.Sprintf("%d", r.Version)
	metrics.RequestsCount.WithLabelValues(clientAddr, r.ApiName, versionStr).Inc()
}

// Decode implements the ProtocolBody interface, allowing the sniffer to capture API
// details without needing to implement detailed decoding for every Kafka API.
// For GenericRequest objects, we just store minimal info and safely handle malformed packets.
func (r *GenericRequest) Decode(pd PacketDecoder, version int16) error {
	// This is a fallback decoder that only stores metadata and doesn't parse
	// all the fields of unknown/unimplemented request types
	r.Version = version
	
	// We skip most field-specific decoding for generic requests
	// But we do attempt to extract ClientID if possible
	try := func() {
		// Most Kafka requests have CorrelationID (int32) followed by ClientID (string)
		// Skip CorrelationID (4 bytes)
		if pd.remaining() > 4 {
			_, err := pd.getInt32()
			if err != nil {
				return
			}
		}
		
		// Try to get ClientID if present
		if pd.remaining() > 2 { // At least need string length
			clientID, err := pd.getString()
			if err != nil {
				return
			}
			r.ClientID = clientID
		}
	}
	
	// Try to extract ClientID but don't fail if we can't
	try()
	
	// For debugging purposes, capture a limited amount of raw bytes
	// But not so many that it becomes a memory issue
	if pd.remaining() > 0 && pd.remaining() < 256 { // Reasonable size limit
		bytes, err := pd.getRawBytes(pd.remaining())
		if err != nil {
			return err
		}
		r.RawBytes = bytes
	} else if pd.remaining() > 0 {
		// If there are remaining bytes but too many to store, just skip them
		// This avoids memory allocation issues with very large/malformed packets
		_, err := pd.getRawBytes(pd.remaining())
		if err != nil {
			return err
		}
	}
	
	return nil
}
