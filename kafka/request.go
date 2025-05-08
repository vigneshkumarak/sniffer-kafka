package kafka

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/d-ulyanov/kafka-sniffer/metrics"
)

var (
	// MaxRequestSize is the maximum size (in bytes) of any Request
	MaxRequestSize int32 = 100 * 1024 * 1024
)

// ProtocolBody represents body of kafka request
type ProtocolBody interface {
	versionedDecoder
	metrics.ClientMetricsCollector
	key() int16
	version() int16
	requiredVersion() Version
}

// Request is a kafka request
type Request struct {
	// Key is a Kafka api key - it defines kind of request (why it called api key?)
	// List of api keys see here: https://kafka.apache.org/protocol#protocol_api_keys
	Key int16

	// Version is a Kafka broker version
	Version int16

	// Is request body length
	BodyLength int32

	CorrelationID int32

	ClientID string

	Body ProtocolBody

	UsePreparedKeyVersion bool
}

// Decode decodes request from packet
func (r *Request) Decode(pd PacketDecoder) (err error) {
	if !r.UsePreparedKeyVersion {
		r.Key, err = pd.getInt16() // +2 bytes
		if err != nil {
			return err
		}
	}

	if !r.UsePreparedKeyVersion {
		r.Version, err = pd.getInt16() // +2 bytes
		if err != nil {
			return err
		}
	}

	r.CorrelationID, err = pd.getInt32() // +4 bytes
	if err != nil {
		return err
	}

	r.ClientID, err = pd.getString() // +2 + len(r.ClientID) bytes
	if err != nil {
		return err
	}

	body := allocateBody(r.Key, r.Version)

	// If  we can't (don't want) to unmarshal request structure - we need to discard the rest bytes
	if body == nil {
		// discard 10 bytes + clientID length
		pd.discard(int(r.BodyLength) - 10 - len(r.ClientID))

		// Skip Body decoding for now
		return nil
	}

	r.Body = body
	if r.Body == nil {
		return PacketDecodingError{fmt.Sprintf("unknown Request key (%d)", r.Key)}
	}

	return r.Body.Decode(pd, r.Version)
}

// DecodeLength decodes length from packet
func DecodeLength(encoded []byte) int32 {
	return int32(binary.BigEndian.Uint32(encoded[:4]))
}

// DecodeKey decodes key from packet. For terminology see kafka reference
func DecodeKey(encoded []byte) int16 {
	return int16(binary.BigEndian.Uint16(encoded[4:6]))
}

// DecodeVersion descodes version from packet
func DecodeVersion(encoded []byte) int16 {
	return int16(binary.BigEndian.Uint16(encoded[6:]))
}

// ExtractHeaderInfo returns a map of header information from packet bytes for logging
func ExtractHeaderInfo(headerBytes []byte) map[string]interface{} {
	info := make(map[string]interface{})
	
	// Make sure we have enough bytes to extract information
	if len(headerBytes) < 8 {
		info["bytes_available"] = len(headerBytes)
		return info
	}
	
	// Extract key header information
	size := DecodeLength(headerBytes)
	key := DecodeKey(headerBytes)
	version := DecodeVersion(headerBytes)
	
	// Add to info map
	info["message_size"] = size
	info["api_key"] = key
	info["api_version"] = version
	
	// Map common API keys to names for easier debugging
	apiName := "Unknown"
	switch key {
	case 0:
		apiName = "Produce"
	case 1:
		apiName = "Fetch"
	case 2:
		apiName = "ListOffsets"
	case 3:
		apiName = "Metadata"
	case 8:
		apiName = "DescribeGroups"
	case 10:
		apiName = "FindCoordinator"
	case 17:
		apiName = "SaslHandshake"
	case 18:
		apiName = "ApiVersions"
	case 36:
		apiName = "SaslAuthenticate"
	}
	info["api_name"] = apiName
	
	return info
}

// DecodeRequest decodes request from packets delivered by reader
func DecodeRequest(r io.Reader) (*Request, int, error) {
	var (
		needReadBytes = 8
		readBytes     = make([]byte, needReadBytes)
	)
	// read bytes to decode length, key, version
	n, err := io.ReadFull(r, readBytes)
	if err != nil {
		return nil, n, err
	}
	if len(readBytes) != needReadBytes {
		return nil, len(readBytes), errors.New("could not read enough bytes to decode length, key, version")
	}

	// length - (key(2 bytes) + version(2 bytes))
	length := DecodeLength(readBytes) - 4
	key := DecodeKey(readBytes)
	version := DecodeVersion(readBytes)

	// Ensure we have a reasonable length value before proceeding
	// Defend against negative lengths, which could cause issues with slice allocation
	if length < 0 {
		return nil, needReadBytes, PacketDecodingError{fmt.Sprintf("invalid message length: %d", length)}
	}

	// Check request size to prevent memory allocation issues
	// 4 is minimum size for CorrelationID
	if length <= 4 || length > MaxRequestSize {
		return nil, int(length) + needReadBytes, PacketDecodingError{fmt.Sprintf("message of length %d too large or too small", length)}
	}

	// We will use a protocol body even for unsupported keys to log and track them
	_ = allocateBody(key, version) // Just check we can allocate a body, but don't use it yet

	// Allocate a slice for the request body - use a reasonable limit
	encodedReq := make([]byte, 0, length)
	// Use a buffer with a set maximum size to prevent memory allocation attacks
	buf := make([]byte, min(int(length), 4096))
	remaining := int(length)
	totalRead := 0

	// Read the message body in chunks to handle large messages safely
	for remaining > 0 {
		readSize := min(remaining, len(buf))
		n, err := io.ReadFull(r, buf[:readSize])
		if err != nil {
			return nil, needReadBytes + totalRead, fmt.Errorf("error reading request body after %d bytes: %w", totalRead, err)
		}
		encodedReq = append(encodedReq, buf[:n]...)
		totalRead += n
		remaining -= n
	}

	bytesRead := needReadBytes + totalRead

	// Create the request struct
	req := &Request{
		BodyLength:            length,
		Key:                   key,
		Version:               version,
		UsePreparedKeyVersion: true,
	}

	// decode request - if it fails, we'll still return the partial request
	err = Decode(encodedReq, req)
	if err != nil {
		// If we got an invalid length error, we'll still return as much as we can
		// but we'll wrap the error to indicate it's a length issue
		if strings.Contains(err.Error(), "invalid length") {
			err = PacketDecodingError{fmt.Sprintf("invalid length error decoding request key %d (version %d): %v", key, version, err)}
		}
		return req, bytesRead, err
	}

	return req, bytesRead, nil
}

// Helper function to get the minimum of two ints
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func allocateBody(key, version int16) ProtocolBody {
	// Return the appropriate request body based on the API key
	// We handle all keys from the Kafka protocol (0-67) as of Kafka 3.0+
	// For the full list of API keys, see: https://kafka.apache.org/protocol#protocol_api_keys
	switch key {
	// Implemented requests (with full decoding support)
	case 0: // Produce
		return &ProduceRequest{}
	case 1: // Fetch
		return &FetchRequest{Version: version}
	case 2: // ListOffsets
		return &ListOffsetsRequest{}
	case 3: // Metadata
		return &MetadataRequest{}
	case 8: // DescribeGroups (in some versions this was OffsetCommit)
		return &DescribeGroupsRequest{}
	case 10: // FindCoordinator
		return &FindCoordinatorRequest{}
	case 18: // ApiVersions
		return &ApiVersionsRequest{}
	case 19: // DeleteTopics
		return &DeleteTopicsRequest{}
	case 32: // DescribeConfigs
		return &DescribeConfigsRequest{}
	
	// Known API keys without full implementation - return GenericRequest
	// These will still be identified correctly but won't decode all fields
	case 4: // LeaderAndIsr
		return &GenericRequest{ApiKey: key, ApiName: "LeaderAndIsr"}
	case 5: // StopReplica
		return &GenericRequest{ApiKey: key, ApiName: "StopReplica"}
	case 6: // UpdateMetadata
		return &GenericRequest{ApiKey: key, ApiName: "UpdateMetadata"}
	case 7: // ControlledShutdown
		return &GenericRequest{ApiKey: key, ApiName: "ControlledShutdown"}
	case 9: // OffsetFetch
		return &GenericRequest{ApiKey: key, ApiName: "OffsetFetch"}
	case 11: // JoinGroup
		return &GenericRequest{ApiKey: key, ApiName: "JoinGroup"}
	case 12: // Heartbeat
		return &GenericRequest{ApiKey: key, ApiName: "Heartbeat"}
	case 13: // LeaveGroup
		return &GenericRequest{ApiKey: key, ApiName: "LeaveGroup"}
	case 14: // SyncGroup
		return &GenericRequest{ApiKey: key, ApiName: "SyncGroup"}
	case 15: // DescribeGroups
		return &GenericRequest{ApiKey: key, ApiName: "DescribeGroups"}
	case 16: // ListGroups
		return &GenericRequest{ApiKey: key, ApiName: "ListGroups"}
	case 17: // SaslHandshake
		return &SaslHandshakeRequest{}
	case 20: // DeleteRecords
		return &GenericRequest{ApiKey: key, ApiName: "DeleteRecords"}
	case 21: // InitProducerId
		return &GenericRequest{ApiKey: key, ApiName: "InitProducerId"}
	case 22: // OffsetForLeaderEpoch
		return &GenericRequest{ApiKey: key, ApiName: "OffsetForLeaderEpoch"}
	case 23: // AddPartitionsToTxn
		return &GenericRequest{ApiKey: key, ApiName: "AddPartitionsToTxn"}
	case 24: // AddOffsetsToTxn
		return &GenericRequest{ApiKey: key, ApiName: "AddOffsetsToTxn"}
	case 25: // EndTxn
		return &GenericRequest{ApiKey: key, ApiName: "EndTxn"}
	case 26: // WriteTxnMarkers
		return &GenericRequest{ApiKey: key, ApiName: "WriteTxnMarkers"}
	case 27: // TxnOffsetCommit
		return &GenericRequest{ApiKey: key, ApiName: "TxnOffsetCommit"}
	case 28: // DescribeAcls
		return &GenericRequest{ApiKey: key, ApiName: "DescribeAcls"}
	case 29: // CreateAcls
		return &GenericRequest{ApiKey: key, ApiName: "CreateAcls"}
	case 30: // DeleteAcls
		return &GenericRequest{ApiKey: key, ApiName: "DeleteAcls"}
	case 31: // DeleteAcls
		return &GenericRequest{ApiKey: key, ApiName: "DeleteAcls"}
	case 33: // AlterConfigs
		return &GenericRequest{ApiKey: key, ApiName: "AlterConfigs"}
	case 34: // AlterReplicaLogDirs
		return &GenericRequest{ApiKey: key, ApiName: "AlterReplicaLogDirs"}
	case 35: // DescribeLogDirs
		return &GenericRequest{ApiKey: key, ApiName: "DescribeLogDirs"}
	case 36: // SaslAuthenticate
		return &SaslAuthenticateRequest{}
	case 37: // CreatePartitions
		return &GenericRequest{ApiKey: key, ApiName: "CreatePartitions"}
	case 38: // CreateDelegationToken
		return &GenericRequest{ApiKey: key, ApiName: "CreateDelegationToken"}
	case 39: // RenewDelegationToken
		return &GenericRequest{ApiKey: key, ApiName: "RenewDelegationToken"}
	case 40: // ExpireDelegationToken
		return &GenericRequest{ApiKey: key, ApiName: "ExpireDelegationToken"}
	case 41: // DescribeDelegationToken
		return &GenericRequest{ApiKey: key, ApiName: "DescribeDelegationToken"}
	case 42: // DeleteGroups
		return &GenericRequest{ApiKey: key, ApiName: "DeleteGroups"}
	case 43: // ElectLeaders
		return &GenericRequest{ApiKey: key, ApiName: "ElectLeaders"}
	case 44: // IncrementalAlterConfigs
		return &GenericRequest{ApiKey: key, ApiName: "IncrementalAlterConfigs"}
	case 45: // AlterPartitionReassignments
		return &GenericRequest{ApiKey: key, ApiName: "AlterPartitionReassignments"}
	case 46: // ListPartitionReassignments
		return &GenericRequest{ApiKey: key, ApiName: "ListPartitionReassignments"}
	case 47: // OffsetDelete
		return &GenericRequest{ApiKey: key, ApiName: "OffsetDelete"}
	case 48: // DescribeClientQuotas
		return &GenericRequest{ApiKey: key, ApiName: "DescribeClientQuotas"}
	case 49: // AlterClientQuotas
		return &GenericRequest{ApiKey: key, ApiName: "AlterClientQuotas"}
	case 50: // DescribeUserScramCredentials
		return &GenericRequest{ApiKey: key, ApiName: "DescribeUserScramCredentials"}
	case 51: // AlterUserScramCredentials
		return &GenericRequest{ApiKey: key, ApiName: "AlterUserScramCredentials"}
	case 52: // VoteRequest
		return &GenericRequest{ApiKey: key, ApiName: "VoteRequest"}
	case 53: // BeginQuorumEpoch
		return &GenericRequest{ApiKey: key, ApiName: "BeginQuorumEpoch"}
	case 54: // EndQuorumEpoch
		return &GenericRequest{ApiKey: key, ApiName: "EndQuorumEpoch"}
	case 55: // DescribeQuorum
		return &GenericRequest{ApiKey: key, ApiName: "DescribeQuorum"}
	case 56: // AlterIsr
		return &GenericRequest{ApiKey: key, ApiName: "AlterIsr"}
	case 57: // UpdateFeatures
		return &GenericRequest{ApiKey: key, ApiName: "UpdateFeatures"}
	case 58: // Envelope
		return &GenericRequest{ApiKey: key, ApiName: "Envelope"}
	case 59: // FetchSnapshot
		return &GenericRequest{ApiKey: key, ApiName: "FetchSnapshot"}
	case 60: // DescribeCluster
		return &GenericRequest{ApiKey: key, ApiName: "DescribeCluster"}
	case 61: // DescribeProducers
		return &GenericRequest{ApiKey: key, ApiName: "DescribeProducers"}
	case 62: // BrokerRegistration
		return &GenericRequest{ApiKey: key, ApiName: "BrokerRegistration"}
	case 63: // BrokerHeartbeat
		return &GenericRequest{ApiKey: key, ApiName: "BrokerHeartbeat"}
	case 64: // UnregisterBroker
		return &GenericRequest{ApiKey: key, ApiName: "UnregisterBroker"}
	case 65: // DescribeTransactions
		return &GenericRequest{ApiKey: key, ApiName: "DescribeTransactions"}
	case 66: // ListTransactions
		return &GenericRequest{ApiKey: key, ApiName: "ListTransactions"}
	case 67: // AllocateProducerIds
		return &GenericRequest{ApiKey: key, ApiName: "AllocateProducerIds"}
	case 68: // ConsumerGroupHeartbeat
		return &GenericRequest{ApiKey: key, ApiName: "ConsumerGroupHeartbeat"}
	case 69: // ConsumerGroupDescribe
		return &GenericRequest{ApiKey: key, ApiName: "ConsumerGroupDescribe"}
	case 71: // GetTelemetrySubscriptions
		return &GenericRequest{ApiKey: key, ApiName: "GetTelemetrySubscriptions"}
	case 72: // PushTelemetry
		return &GenericRequest{ApiKey: key, ApiName: "PushTelemetry"}
	case 74: // ListClientMetricsResources
		return &GenericRequest{ApiKey: key, ApiName: "ListClientMetricsResources"}
	case 75: // DescribeTopicPartitions
		return &GenericRequest{ApiKey: key, ApiName: "DescribeTopicPartitions"}
	case 80: // AddRaftVoter
		return &GenericRequest{ApiKey: key, ApiName: "AddRaftVoter"}
	case 81: // RemoveRaftVoter
		return &GenericRequest{ApiKey: key, ApiName: "RemoveRaftVoter"}
	default:
		// For any future API keys we don't know about yet
		return &GenericRequest{ApiKey: key, ApiName: fmt.Sprintf("Unknown(%d)", key)}
	}
}
