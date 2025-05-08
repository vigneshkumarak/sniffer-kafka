package kafka

import (
	"fmt"
	"github.com/d-ulyanov/kafka-sniffer/metrics"
)

// ListOffsetsRequest is used to get the offset for a topic/partition at a given time
type ListOffsetsRequest struct {
	ReplicaID      int32
	Topics         []ListOffsetsTopic
	Version        int16
	IsolationLevel int8 // Only used in v2+
}

// ListOffsetsTopic contains the topic name and partitions to list offsets for
type ListOffsetsTopic struct {
	Topic      string
	Partitions []ListOffsetsPartition
}

// ListOffsetsPartition contains a partition and time to list offset for
type ListOffsetsPartition struct {
	Partition int32
	Time      int64 // -1 for earliest, -2 for latest
}

// key returns the Kafka API key for ListOffsets
func (r *ListOffsetsRequest) key() int16 {
	return 2
}

// version returns the Kafka request version
func (r *ListOffsetsRequest) version() int16 {
	return 0
}

// requiredVersion states what the minimum required version is
func (r *ListOffsetsRequest) requiredVersion() Version {
	return V0_8_2_0
}

// Decode deserializes a ListOffsets request from the given PacketDecoder
func (r *ListOffsetsRequest) Decode(pd PacketDecoder, version int16) error {
	// Store the version number for metrics
	r.Version = version

	// Safety check to prevent panics
	if pd == nil {
		r.Topics = []ListOffsetsTopic{}
		return nil
	}

	// Use recover to handle any panics during decoding
	func() {
		defer func() {
			if rec := recover(); rec != nil {
				// If we panic during decoding, use empty data
				r.Topics = []ListOffsetsTopic{}
			}
		}()

		// Basic decoding approach, skip version-specific checks to avoid protocol issues
		replicaID, err := pd.getInt32()
		if err != nil {
			panic("Error decoding ReplicaID")
		}
		r.ReplicaID = replicaID

		topicCount, err := pd.getArrayLength()
		if err != nil {
			panic("Error decoding topic count")
		}

		// Validate topicCount to prevent panics from malformed packets
		if topicCount < 0 || topicCount > 10000 {
			panic("Invalid topic count")
		}

		r.Topics = make([]ListOffsetsTopic, topicCount)
		for i := range r.Topics {
			topic, err := pd.getString()
			if err != nil {
				panic("Error decoding topic string")
			}
			r.Topics[i].Topic = topic

			partitionCount, err := pd.getArrayLength()
			if err != nil {
				panic("Error decoding partition count")
			}

			// Validate partitionCount
			if partitionCount < 0 || partitionCount > 10000 {
				panic("Invalid partition count")
			}

			r.Topics[i].Partitions = make([]ListOffsetsPartition, partitionCount)
			for j := range r.Topics[i].Partitions {
				partition, err := pd.getInt32()
				if err != nil {
					panic("Error decoding partition")
				}
				r.Topics[i].Partitions[j].Partition = partition

				time, err := pd.getInt64()
				if err != nil {
					panic("Error decoding time")
				}
				r.Topics[i].Partitions[j].Time = time
			}
		}
	}()

	// Skip any remaining bytes to be forward compatible
	if pd.remaining() > 0 {
		// Best effort to skip remaining bytes, ignore errors
		_, _ = pd.getRawBytes(pd.remaining())
	}

	return nil
}

// ExtractTopics returns a list of topics in this request
func (r *ListOffsetsRequest) ExtractTopics() []string {
	topics := make([]string, len(r.Topics))
	for i, topic := range r.Topics {
		topics[i] = topic.Topic
	}
	return topics
}

// CollectClientMetrics implements the ClientMetricsCollector interface
func (r *ListOffsetsRequest) CollectClientMetrics(clientIP string) {
	// Include API version in request metrics
	versionStr := fmt.Sprintf("%d", r.Version)
	metrics.RequestsCount.WithLabelValues(clientIP, "list_offsets", versionStr).Inc()
	
	// Collect metrics for ListOffsets operation - track topic relations
	for _, topic := range r.Topics {
		metrics.AddConsumerTopicRelationInfo(clientIP, topic.Topic)
	}
}
