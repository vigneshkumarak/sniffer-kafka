package kafka

import "github.com/d-ulyanov/kafka-sniffer/metrics"

// DeleteTopicsRequest is used to delete topics in Kafka
type DeleteTopicsRequest struct {
	Topics  []string
	Timeout int32
}

// key returns the Kafka API key for DeleteTopics
func (r *DeleteTopicsRequest) key() int16 {
	return 20
}

// version returns the Kafka request version
func (r *DeleteTopicsRequest) version() int16 {
	return 0
}

// requiredVersion states what the minimum required version is
func (r *DeleteTopicsRequest) requiredVersion() Version {
	return V0_10_0_0
}

// Decode deserializes a DeleteTopics request from the given PacketDecoder
func (r *DeleteTopicsRequest) Decode(pd PacketDecoder, version int16) error {
	topicCount, err := pd.getArrayLength()
	if err != nil {
		return err
	}

	if topicCount == 0 {
		return nil
	}

	r.Topics = make([]string, topicCount)
	for i := 0; i < topicCount; i++ {
		topic, err := pd.getString()
		if err != nil {
			return err
		}
		r.Topics[i] = topic
	}

	timeout, err := pd.getInt32()
	if err != nil {
		return err
	}
	r.Timeout = timeout

	return nil
}

// ExtractTopics returns a list of topics in this request
func (r *DeleteTopicsRequest) ExtractTopics() []string {
	return r.Topics
}

// CollectClientMetrics implements the ClientMetricsCollector interface
func (r *DeleteTopicsRequest) CollectClientMetrics(clientIP string) {
	// A client deleting topics is likely to be an admin
	for _, topic := range r.Topics {
		metrics.AddActiveTopicInfo(clientIP, topic)
	}
}
