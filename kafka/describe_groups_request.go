package kafka


// DescribeGroupsRequest is used to describe consumer groups
type DescribeGroupsRequest struct {
	Groups []string
}

// key returns the Kafka API key for DescribeGroups
func (r *DescribeGroupsRequest) key() int16 {
	return 8
}

// version returns the Kafka request version
func (r *DescribeGroupsRequest) version() int16 {
	return 0
}

// requiredVersion states what the minimum required version is
func (r *DescribeGroupsRequest) requiredVersion() Version {
	return V0_9_0_0
}

// Decode deserializes a DescribeGroups request from the given PacketDecoder
func (r *DescribeGroupsRequest) Decode(pd PacketDecoder, version int16) error {
	groupsLen, err := pd.getArrayLength()
	if err != nil {
		return err
	}

	if groupsLen == 0 {
		return nil
	}

	r.Groups = make([]string, groupsLen)
	for i := 0; i < groupsLen; i++ {
		group, err := pd.getString()
		if err != nil {
			return err
		}
		r.Groups[i] = group
	}

	return nil
}

// ExtractTopics returns an empty list as DescribeGroups doesn't directly relate to topics
func (r *DescribeGroupsRequest) ExtractTopics() []string {
	return []string{}
}

// CollectClientMetrics implements the ClientMetricsCollector interface
func (r *DescribeGroupsRequest) CollectClientMetrics(clientIP string) {
	// No specific topic metrics for describe groups operations
}
