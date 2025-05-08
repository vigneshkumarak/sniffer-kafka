package kafka

import "github.com/d-ulyanov/kafka-sniffer/metrics"

// CreateTopicsRequest is used to create topics in Kafka
type CreateTopicsRequest struct {
	Topics                 []CreateTopicRequest
	Timeout                int32
	ValidateOnly           bool
}

// CreateTopicRequest contains details for a single topic creation
type CreateTopicRequest struct {
	Topic             string
	NumPartitions     int32
	ReplicationFactor int16
	ReplicaAssignment map[int32][]int32
	ConfigEntries     map[string]string
}

// key returns the Kafka API key for CreateTopics
func (r *CreateTopicsRequest) key() int16 {
	return 19
}

// version returns the Kafka request version
func (r *CreateTopicsRequest) version() int16 {
	return 0
}

// requiredVersion states what the minimum required version is
func (r *CreateTopicsRequest) requiredVersion() Version {
	return V0_10_0_0
}

// Decode deserializes a CreateTopics request from the given PacketDecoder
func (r *CreateTopicsRequest) Decode(pd PacketDecoder, version int16) error {
	topicCount, err := pd.getArrayLength()
	if err != nil {
		return err
	}

	r.Topics = make([]CreateTopicRequest, topicCount)
	for i := range r.Topics {
		topic, err := pd.getString()
		if err != nil {
			return err
		}
		r.Topics[i].Topic = topic

		numPartitions, err := pd.getInt32()
		if err != nil {
			return err
		}
		r.Topics[i].NumPartitions = numPartitions

		replicationFactor, err := pd.getInt16()
		if err != nil {
			return err
		}
		r.Topics[i].ReplicationFactor = replicationFactor

		// Skip replica assignment and config entries for simplicity
		// In a full implementation, we would decode these fields as well

		// Skip replica assignment
		replicaCount, err := pd.getArrayLength()
		if err != nil {
			return err
		}
		for j := 0; j < replicaCount; j++ {
			// Skip partition
			if _, err := pd.getInt32(); err != nil {
				return err
			}
			// Skip replicas array
			replicasCount, err := pd.getArrayLength()
			if err != nil {
				return err
			}
			for k := 0; k < replicasCount; k++ {
				if _, err := pd.getInt32(); err != nil {
					return err
				}
			}
		}

		// Skip config entries
		configCount, err := pd.getArrayLength()
		if err != nil {
			return err
		}
		for j := 0; j < configCount; j++ {
			// Skip config name
			if _, err := pd.getString(); err != nil {
				return err
			}
			// Skip config value
			if _, err := pd.getString(); err != nil {
				return err
			}
		}
	}

	timeout, err := pd.getInt32()
	if err != nil {
		return err
	}
	r.Timeout = timeout

	// ValidateOnly is only available in version 1+
	if version >= 1 {
		validateOnly, err := pd.getBool()
		if err != nil {
			return err
		}
		r.ValidateOnly = validateOnly
	}

	return nil
}

// ExtractTopics returns a list of topics in this request
func (r *CreateTopicsRequest) ExtractTopics() []string {
	topics := make([]string, len(r.Topics))
	for i, topic := range r.Topics {
		topics[i] = topic.Topic
	}
	return topics
}

// CollectClientMetrics implements the ClientMetricsCollector interface
func (r *CreateTopicsRequest) CollectClientMetrics(clientIP string) {
	// A client creating topics is likely to be a producer
	for _, topic := range r.Topics {
		metrics.AddProducerTopicRelationInfo(clientIP, topic.Topic)
	}
}
