package kafka

import (
	"fmt"
	"github.com/d-ulyanov/kafka-sniffer/metrics"
)

// FindCoordinatorRequest is used to find the coordinator for a group or transaction
type FindCoordinatorRequest struct {
	Version        int16
	CoordinatorKey string
	CoordinatorType byte // 0 = consumer group, 1 = transaction
}

// key returns the Kafka API key for FindCoordinator
func (r *FindCoordinatorRequest) key() int16 {
	return 10
}

// version returns the Kafka request version
func (r *FindCoordinatorRequest) version() int16 {
	return r.Version
}

// requiredVersion states what the minimum required version is
func (r *FindCoordinatorRequest) requiredVersion() Version {
	return V0_9_0_0
}

// Decode deserializes a FindCoordinator request from the given PacketDecoder
func (r *FindCoordinatorRequest) Decode(pd PacketDecoder, version int16) error {
	r.Version = version
	key, err := pd.getString()
	if err != nil {
		return err
	}
	r.CoordinatorKey = key

	// In version 1+, there's a coordinator type field
	if version >= 1 {
		coordinatorType, err := pd.getInt8()
		if err != nil {
			return err
		}
		r.CoordinatorType = byte(coordinatorType)
	} else {
		// In version 0, it was always for a consumer group
		r.CoordinatorType = 0
	}

	return nil
}

// ExtractTopics returns an empty list as FindCoordinator doesn't directly relate to topics
func (r *FindCoordinatorRequest) ExtractTopics() []string {
	return []string{}
}

// CollectClientMetrics implements the ClientMetricsCollector interface
func (r *FindCoordinatorRequest) CollectClientMetrics(clientIP string) {
	// Add version information to metrics
	versionStr := fmt.Sprintf("%d", r.Version)
	metrics.RequestsCount.WithLabelValues(clientIP, "FindCoordinator", versionStr).Inc()
}