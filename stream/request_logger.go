package stream

import (
	"fmt"
	"log"
	
	"github.com/d-ulyanov/kafka-sniffer/kafka"
	"github.com/d-ulyanov/kafka-sniffer/metrics"
)

// logRequestHeaderDetails prints information about Kafka request headers in a simple format
func logRequestHeaderDetails(req *kafka.Request, srcHost string, _ ...string) { // Simplified parameters, ignoring srcPort, dstHost, dstPort
	// Get API name
	apiName := getApiName(req.Key)
	
	// Track request version information for Grafana dashboard
	version := fmt.Sprintf("%d", req.Version)
	
	// Track API version with request type for Grafana dashboard visualization
	// Update the RequestsCount metric with version information for the dashboard
	metrics.RequestsCount.WithLabelValues(srcHost, apiName, version).Inc()
	// Log in the requested format based on request type
	switch body := req.Body.(type) {
	case *kafka.SaslHandshakeRequest:
		log.Printf("Client: %s, Key: %d, Version: %d, ClientID: %s, API: %s, Mechanism: %s",
			srcHost, req.Key, req.Version, req.ClientID, apiName, body.Mechanism)
	
	case *kafka.ApiVersionsRequest:
		if body.ClientSoftwareName != "" {
			log.Printf("Client: %s, Key: %d, Version: %d, ClientID: %s, API: %s, Software: %s/%s",
				srcHost, req.Key, req.Version, req.ClientID, apiName, 
				body.ClientSoftwareName, body.ClientSoftwareVersion)
		} else {
			log.Printf("Client: %s, Key: %d, Version: %d, ClientID: %s, API: %s",
				srcHost, req.Key, req.Version, req.ClientID, apiName)
		}
	
	case *kafka.SaslAuthenticateRequest:
		if body.Username != "" {
			log.Printf("Client: %s, Key: %d, Version: %d, ClientID: %s, API: %s, Username: %s, Mechanism: %s",
				srcHost, req.Key, req.Version, req.ClientID, apiName, body.Username, body.Mechanism)
		} else {
			log.Printf("Client: %s, Key: %d, Version: %d, ClientID: %s, API: %s",
				srcHost, req.Key, req.Version, req.ClientID, apiName)
		}
	
	default:
		log.Printf("Client: %s, Key: %d, Version: %d, ClientID: %s, API: %s",
			srcHost, req.Key, req.Version, req.ClientID, apiName)
	}
	
	// No need for additional detailed printing
}

// logRawSaslAuth logs username from raw SASL authentication
func logRawSaslAuth(clientIP string, mechanism string, username string) {
	// Just log the extracted information without detailed debugging
	log.Printf("Client: %s, Raw SASL Auth, Mechanism: %s, Username: %s",
		clientIP, mechanism, username)
}

// logAuthDetails logs authentication information in a simplified format
func logAuthDetails(req *kafka.Request, clientIP string) {
	switch req.Key {
	case 36: // SaslAuthenticate
		if auth, ok := req.Body.(*kafka.SaslAuthenticateRequest); ok {
			// If username is available in the request, log and track it
			if auth.Username != "" {
				// Track this authentication in prometheus metrics
				metrics.TrackSaslAuthentication(clientIP, auth.Mechanism, auth.Username)
			} else if len(auth.SaslAuthBytes) > 2 {
				// Try extraction for PLAIN auth if direct username isn't available
				if auth.SaslAuthBytes[0] == 0 {
					// Find the second null byte
					usernameStart := 1
					usernameEnd := -1
					
					for i := 1; i < len(auth.SaslAuthBytes); i++ {
						if auth.SaslAuthBytes[i] == 0 {
							usernameEnd = i
							break
						}
					}
					
					if usernameEnd > usernameStart {
						username := string(auth.SaslAuthBytes[usernameStart:usernameEnd])
						// Track this in metrics
						metrics.TrackSaslAuthentication(clientIP, "PLAIN", username)
					}
				}
			}
		}
	}
}

// getApiName maps API keys to human-readable names based on the Kafka protocol
func getApiName(key int16) string {
	apiNames := map[int16]string{
		0:  "Produce",
		1:  "Fetch",
		2:  "ListOffsets",
		3:  "Metadata",
		4:  "LeaderAndIsr",
		5:  "StopReplica",
		6:  "UpdateMetadata",
		7:  "ControlledShutdown",
		8:  "OffsetCommit",
		9:  "OffsetFetch",
		10: "FindCoordinator",
		11: "JoinGroup",
		12: "Heartbeat",
		13: "LeaveGroup",
		14: "SyncGroup",
		15: "DescribeGroups",
		16: "ListGroups",
		17: "SaslHandshake",
		18: "ApiVersions",
		19: "CreateTopics",
		20: "DeleteTopics",
		21: "DeleteRecords",
		22: "InitProducerId",
		23: "OffsetForLeaderEpoch",
		24: "AddPartitionsToTxn",
		25: "AddOffsetsToTxn",
		26: "EndTxn",
		27: "WriteTxnMarkers",
		28: "TxnOffsetCommit",
		29: "DescribeAcls",
		30: "CreateAcls",
		31: "DeleteAcls",
		32: "DescribeConfigs",
		33: "AlterConfigs",
		34: "AlterReplicaLogDirs",
		35: "DescribeLogDirs",
		36: "SaslAuthenticate",
		37: "CreatePartitions",
		38: "CreateDelegationToken",
		39: "RenewDelegationToken",
		40: "ExpireDelegationToken",
		41: "DescribeDelegationToken",
		42: "DeleteGroups",
		43: "ElectLeaders",
		44: "IncrementalAlterConfigs",
		45: "AlterPartitionReassignments",
		46: "ListPartitionReassignments",
		47: "OffsetDelete",
		48: "DescribeClientQuotas",
		49: "AlterClientQuotas",
		50: "DescribeUserScramCredentials",
		51: "AlterUserScramCredentials",
		52: "Vote",
		53: "BeginQuorumEpoch",
		54: "EndQuorumEpoch",
		55: "DescribeQuorum",
		56: "AlterPartition",
		57: "UpdateFeatures",
		58: "Envelope",
		59: "FetchSnapshot",
		60: "DescribeCluster",
		61: "DescribeProducers",
		62: "BrokerRegistration",
		63: "BrokerHeartbeat",
		64: "UnregisterBroker",
		65: "DescribeTransactions",
		66: "ListTransactions",
		67: "AllocateProducerIds",
	}
	
	if name, exists := apiNames[key]; exists {
		return name
	}
	
	return fmt.Sprintf("Unknown(%d)", key)
}
