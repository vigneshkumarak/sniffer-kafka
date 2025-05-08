package kafka

import (
	"fmt"
	"github.com/d-ulyanov/kafka-sniffer/metrics"
)

// DescribeConfigsRequest is used to get the configuration for resources
type DescribeConfigsRequest struct {
	Version        int16
	Resources    []DescribeConfigsResource
	IncludeSynonyms bool
}

// DescribeConfigsResource identifies a resource to describe configs for
type DescribeConfigsResource struct {
	ResourceType int8 // 0 = Unknown, 1 = Topic, 2 = Broker, 3 = Broker Logger
	ResourceName string
	ConfigNames  []string
}

// key returns the Kafka API key for DescribeConfigs
func (r *DescribeConfigsRequest) key() int16 {
	return 32
}

// version returns the Kafka request version
func (r *DescribeConfigsRequest) version() int16 {
	return r.Version
}

// requiredVersion states what the minimum required version is
func (r *DescribeConfigsRequest) requiredVersion() Version {
	return V0_11_0_0
}

// Decode deserializes a DescribeConfigs request from the given PacketDecoder
func (r *DescribeConfigsRequest) Decode(pd PacketDecoder, version int16) error {
	r.Version = version
	resourceCount, err := pd.getArrayLength()
	if err != nil {
		return err
	}

	r.Resources = make([]DescribeConfigsResource, resourceCount)
	for i := range r.Resources {
		resourceType, err := pd.getInt8()
		if err != nil {
			return err
		}
		r.Resources[i].ResourceType = resourceType

		resourceName, err := pd.getString()
		if err != nil {
			return err
		}
		r.Resources[i].ResourceName = resourceName

		configNamesCount, err := pd.getArrayLength()
		if err != nil {
			return err
		}

		// Skip if there are no config names or if count is invalid
		if configNamesCount <= 0 || configNamesCount > 10000 {
			// Set a reasonable upper limit to prevent allocating huge slices
			if configNamesCount > 10000 {
				return PacketDecodingError{"invalid configNames array length"}
			}
			continue
		}

		r.Resources[i].ConfigNames = make([]string, configNamesCount)
		for j := 0; j < configNamesCount; j++ {
			configName, err := pd.getString()
			if err != nil {
				return err
			}
			r.Resources[i].ConfigNames[j] = configName
		}
	}

	if version >= 1 {
		includeSynonyms, err := pd.getBool()
		if err != nil {
			return err
		}
		r.IncludeSynonyms = includeSynonyms
	}

	return nil
}

// ExtractTopics returns a list of topics in this request
func (r *DescribeConfigsRequest) ExtractTopics() []string {
	var topics []string
	for _, resource := range r.Resources {
		// ResourceType 1 = Topic
		if resource.ResourceType == 1 {
			topics = append(topics, resource.ResourceName)
		}
	}
	return topics
}

// CollectClientMetrics implements the ClientMetricsCollector interface
func (r *DescribeConfigsRequest) CollectClientMetrics(clientIP string) {
	// Include version information in metrics
	versionStr := fmt.Sprintf("%d", r.Version)
	metrics.RequestsCount.WithLabelValues(clientIP, "DescribeConfigs", versionStr).Inc()
	
	// For topic config requests, record interest in these topics
	for _, resource := range r.Resources {
		// ResourceType 1 = Topic
		if resource.ResourceType == 1 {
			metrics.AddActiveTopicInfo(clientIP, resource.ResourceName)
		}
	}
}