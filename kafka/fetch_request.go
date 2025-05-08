package kafka

import (
	"fmt"
	"github.com/d-ulyanov/kafka-sniffer/metrics"
)

type fetchRequestBlock struct {
	Version            int16
	currentLeaderEpoch int32
	fetchOffset        int64
	logStartOffset     int64
	maxBytes           int32
}

func (b *fetchRequestBlock) decode(pd PacketDecoder, version int16) (err error) {
	b.Version = version
	if b.Version >= 9 {
		if b.currentLeaderEpoch, err = pd.getInt32(); err != nil {
			return err
		}
	}
	if b.fetchOffset, err = pd.getInt64(); err != nil {
		return err
	}
	if b.Version >= 5 {
		if b.logStartOffset, err = pd.getInt64(); err != nil {
			return err
		}
	}
	if b.maxBytes, err = pd.getInt32(); err != nil {
		return err
	}
	return nil
}

// FetchRequest (API key 1) will fetch Kafka messages. Version 3 introduced the MaxBytes field. See
// https://issues.apache.org/jira/browse/KAFKA-2063 for a discussion of the issues leading up to that.  The KIP is at
// https://cwiki.apache.org/confluence/display/KAFKA/KIP-74%3A+Add+Fetch+Response+Size+Limit+in+Bytes
type FetchRequest struct {
	MaxWaitTime  int32
	MinBytes     int32
	MaxBytes     int32
	Version      int16
	Isolation    IsolationLevel
	SessionID    int32
	SessionEpoch int32
	blocks       map[string]map[int32]*fetchRequestBlock
	forgotten    map[string][]int32
	RackID       string
}

// IsolationLevel is a setting for reliability
type IsolationLevel int8

// ExtractTopics returns a list of all topics from request
func (r *FetchRequest) ExtractTopics() []string {
	var topics []string
	for k := range r.blocks {
		topics = append(topics, k)
	}

	return topics
}

// GetRequestedBlocksCount returns a total amount of blocks from fetch request
func (r *FetchRequest) GetRequestedBlocksCount() (blocksCount int) {
	for _, partition := range r.blocks {
		blocksCount += len(partition)
	}
	return
}

// Decode retrieves kafka fetch request from packet
func (r *FetchRequest) Decode(pd PacketDecoder, version int16) (err error) {
	r.Version = version

	if _, err = pd.getInt32(); err != nil {
		return err
	}
	if r.MaxWaitTime, err = pd.getInt32(); err != nil {
		return err
	}
	if r.MinBytes, err = pd.getInt32(); err != nil {
		return err
	}
	if r.Version >= 3 {
		if r.MaxBytes, err = pd.getInt32(); err != nil {
			return err
		}
	}
	if r.Version >= 4 {
		var isolation int8
		isolation, err = pd.getInt8()
		if err != nil {
			return err
		}
		r.Isolation = IsolationLevel(isolation)
	}
	if r.Version >= 7 {
		r.SessionID, err = pd.getInt32()
		if err != nil {
			return err
		}
		r.SessionEpoch, err = pd.getInt32()
		if err != nil {
			return err
		}
	}
	topicCount, err := pd.getArrayLength()
	if err != nil {
		return err
	}
	if topicCount == 0 {
		return nil
	}
	r.blocks = make(map[string]map[int32]*fetchRequestBlock)
	for i := 0; i < topicCount; i++ {
		var topic string
		topic, err = pd.getString()
		if err != nil {
			return err
		}
		var partitionCount int
		partitionCount, err = pd.getArrayLength()
		if err != nil {
			return err
		}
		r.blocks[topic] = make(map[int32]*fetchRequestBlock)
		for j := 0; j < partitionCount; j++ {
			var partition int32
			partition, err = pd.getInt32()
			if err != nil {
				return err
			}
			fetchBlock := &fetchRequestBlock{}
			if err = fetchBlock.decode(pd, r.Version); err != nil {
				return err
			}
			r.blocks[topic][partition] = fetchBlock
		}
	}

	if r.Version >= 7 {
		var forgottenCount int
		forgottenCount, err = pd.getArrayLength()
		if err != nil {
			return err
		}
		r.forgotten = make(map[string][]int32)
		for i := 0; i < forgottenCount; i++ {
			var topic string
			topic, err = pd.getString()
			if err != nil {
				return err
			}
			var partitionCount int
			partitionCount, err = pd.getArrayLength()
			if err != nil {
				return err
			}
			r.forgotten[topic] = make([]int32, partitionCount)

			for j := 0; j < partitionCount; j++ {
				var partition int32
				partition, err = pd.getInt32()
				if err != nil {
					return err
				}
				r.forgotten[topic][j] = partition
			}
		}
	}

	if r.Version >= 11 {
		r.RackID, err = pd.getString()
		if err != nil {
			return err
		}
	}

	return nil
}

// CollectClientMetrics collects metrics associated with client
func (r *FetchRequest) CollectClientMetrics(srcHost string) {
	// Include API version in metrics
	versionStr := fmt.Sprintf("%d", r.Version)
	metrics.RequestsCount.WithLabelValues(srcHost, "fetch", versionStr).Inc()

	blocksCount := r.GetRequestedBlocksCount()
	metrics.BlocksRequested.WithLabelValues(srcHost).Add(float64(blocksCount))
}

func (r *FetchRequest) key() int16 {
	return 1
}

func (r *FetchRequest) version() int16 {
	return r.Version
}

func (r *FetchRequest) requiredVersion() Version {
	switch r.Version {
	case 0:
		return MinVersion
	case 1:
		return V0_9_0_0
	case 2:
		return V0_10_0_0
	case 3:
		return V0_10_1_0
	case 4, 5:
		return V0_11_0_0
	case 6:
		return V1_0_0_0
	case 7:
		return V1_1_0_0
	case 8:
		return V2_0_0_0
	case 9, 10:
		return V2_1_0_0
	case 11:
		return V2_3_0_0
	default:
		return MaxVersion
	}
}

// AddBlock adds message block to fetch request
func (r *FetchRequest) AddBlock(topic string, partitionID int32, fetchOffset int64, maxBytes int32) {
	if r.blocks == nil {
		r.blocks = make(map[string]map[int32]*fetchRequestBlock)
	}

	if r.Version >= 7 && r.forgotten == nil {
		r.forgotten = make(map[string][]int32)
	}

	if r.blocks[topic] == nil {
		r.blocks[topic] = make(map[int32]*fetchRequestBlock)
	}

	tmp := new(fetchRequestBlock)
	tmp.Version = r.Version
	tmp.maxBytes = maxBytes
	tmp.fetchOffset = fetchOffset
	if r.Version >= 9 {
		tmp.currentLeaderEpoch = int32(-1)
	}

	r.blocks[topic][partitionID] = tmp
}
