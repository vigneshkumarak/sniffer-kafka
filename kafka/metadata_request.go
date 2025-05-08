package kafka

import (
	"fmt"
	"github.com/d-ulyanov/kafka-sniffer/metrics"
)

// MetadataRequest is used to get information about topics and brokers
type MetadataRequest struct {
	Topics          []string
	AllowAutoTopicCreation bool   // v4+
	IncludeClusterAuthorizedOperations bool // v8+
	IncludeTopicAuthorizedOperations bool // v8+
	IncludeTags bool // v11+
	Version     int16
}

// key returns the Kafka API key for Metadata
func (r *MetadataRequest) key() int16 {
	return 3
}

// version returns the Kafka request version
func (r *MetadataRequest) version() int16 {
	return r.Version
}

// requiredVersion states what the minimum required version is
func (r *MetadataRequest) requiredVersion() Version {
	return V0_8_2_0
}

// Decode deserializes a Metadata request from the given PacketDecoder
func (r *MetadataRequest) Decode(pd PacketDecoder, version int16) error {
	// Store version for metrics but use simpler decoding to avoid protocol issues
	r.Version = version

	// Safety check to prevent panics
	if pd == nil {
		r.Topics = []string{}
		return nil
	}

	// Basic decoding that works across all versions without protocol alignment issues
	topicCount, err := pd.getArrayLength()
	if err != nil {
		// Fallback to empty topics list on error
		r.Topics = []string{}
		return nil
	}

	// Validate topicCount to prevent panics from malformed packets
	if topicCount <= 0 || topicCount > 10000 {
		// Instead of failing, just use an empty list
		r.Topics = []string{}
		return nil
	}

	// Use defer-recover to protect against any panics during decoding
	var topicsDecoded bool
	func() {
		defer func() {
			if rec := recover(); rec != nil {
				// If we panic during decoding, reset to empty list
				r.Topics = []string{}
				topicsDecoded = false
			}
		}()

		// Now try to decode the topics
		r.Topics = make([]string, topicCount)
		for i := range r.Topics {
			topic, err := pd.getString()
			if err != nil {
				// On error, we'll fall back to the recover block
				panic("Error decoding topic string")
			}
			r.Topics[i] = topic
		}
		topicsDecoded = true
	}()

	// If topics were not successfully decoded, skip remaining bytes
	if !topicsDecoded && pd.remaining() > 0 {
		// Best effort to skip remaining bytes
		_, _ = pd.getRawBytes(pd.remaining())
	}

	return nil
}

// ExtractTopics returns a list of topics in this request
func (r *MetadataRequest) ExtractTopics() []string {
	return r.Topics
}

// CollectClientMetrics implements the ClientMetricsCollector interface
func (r *MetadataRequest) CollectClientMetrics(clientIP string) {
	// Include API version in metrics
	versionStr := fmt.Sprintf("%d", r.Version)
	metrics.RequestsCount.WithLabelValues(clientIP, "metadata", versionStr).Inc()
	
	// Collect metadata request metrics for topic relationships
	for _, topic := range r.Topics {
		if topic != "" {
			metrics.AddActiveTopicInfo(clientIP, topic)
		}
	}
}
