package kafka

import (
	"fmt"
	"github.com/d-ulyanov/kafka-sniffer/metrics"
)

// ApiVersionsRequest is used by clients to discover which versions
// of each API are supported by a Kafka broker
type ApiVersionsRequest struct {
	Version int16
	ClientSoftwareName    string // v3+
	ClientSoftwareVersion string // v3+
}

// key returns the Kafka API key for ApiVersions
func (r *ApiVersionsRequest) key() int16 {
	return 18 // ApiVersions key
}

// version returns the Kafka request version
func (r *ApiVersionsRequest) version() int16 {
	return r.Version
}

// requiredVersion states what the minimum required version is
func (r *ApiVersionsRequest) requiredVersion() Version {
	return V0_10_0_0
}

// Decode deserializes an ApiVersions request from the given PacketDecoder
func (r *ApiVersionsRequest) Decode(pd PacketDecoder, version int16) error {
	// Store version for metrics
	r.Version = version

	// Safety check to prevent panic
	if pd == nil {
		return nil
	}

	// Version 3 added client software name and version - attempt to decode but don't fail on errors
	if version >= 3 && pd.remaining() > 0 {
		// Use recover to handle any panics during parsing
		func() {
			defer func() {
				recover() // Catch any panics
			}()
			
			clientSoftwareName, err := pd.getNullableString()
			if err == nil && clientSoftwareName != nil {
				r.ClientSoftwareName = *clientSoftwareName
			}

			clientSoftwareVersion, err := pd.getNullableString()
			if err == nil && clientSoftwareVersion != nil {
				r.ClientSoftwareVersion = *clientSoftwareVersion
			}
		}()
	}

	// Skip any remaining bytes to be forward compatible
	if pd.remaining() > 0 {
		_, err := pd.getRawBytes(pd.remaining())
		if err != nil {
			return err
		}
	}

	return nil
}

// CollectClientMetrics implements the ClientMetricsCollector interface
func (r *ApiVersionsRequest) CollectClientMetrics(clientIP string) {
	// Include API version in metrics
	versionStr := fmt.Sprintf("%d", r.Version)
	metrics.RequestsCount.WithLabelValues(clientIP, "api_versions", versionStr).Inc()
	
	// If we have client software information, track it in the metrics
	if r.ClientSoftwareName != "" {
		metricsClientName := r.ClientSoftwareName
		metricsClientVersion := r.ClientSoftwareVersion
		
		// Track client software info in metrics
		metrics.ClientSoftwareInfo.WithLabelValues(clientIP, metricsClientName, metricsClientVersion).Inc()
	}
}