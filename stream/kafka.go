package stream

import (
	"bufio"
	"encoding/binary"
	kafkalog "github.com/d-ulyanov/kafka-sniffer/kafka"
	"fmt"
	"io"
	"log"

	"github.com/d-ulyanov/kafka-sniffer/kafka"
	"github.com/d-ulyanov/kafka-sniffer/metrics"

	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

// We don't need this function anymore as we've simplified buffer handling

// KafkaStreamFactory implements tcpassembly.StreamFactory
type KafkaStreamFactory struct {
	metricsStorage *metrics.Storage
	verbose        bool
}

// NewKafkaStreamFactory assembles streams
func NewKafkaStreamFactory(metricsStorage *metrics.Storage, verbose bool) *KafkaStreamFactory {
	return &KafkaStreamFactory{metricsStorage: metricsStorage, verbose: verbose}
}

// New assembles new stream
func (h *KafkaStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	s := &KafkaStream{
		net:            net,
		transport:      transport,
		r:              tcpreader.NewReaderStream(),
		metricsStorage: h.metricsStorage,
		verbose:        h.verbose,
	}

	go s.run() // Important... we must guarantee that data from the reader stream is read.

	return &s.r
}

// KafkaStream will handle the actual decoding of http requests.
type KafkaStream struct {
	net, transport gopacket.Flow
	r              tcpreader.ReaderStream
	metricsStorage *metrics.Storage
	verbose        bool
	clientAddress  string
	currentUsername string
	currentMechanism string
}

// truncateBytes returns a string representation of byte array, truncated to maxLen if needed
// We don't need this function as we've simplified the logging


// valueOrNil safely returns the value of a string pointer or "nil" if it's nil
func valueOrNil(s *string) interface{} {
	if s == nil {
		return "nil"
	}
	return *s
}

func (h *KafkaStream) run() {
	// Initialize clientAddress at the start of processing
	h.clientAddress = h.net.Src().String()
	
	srcHost := fmt.Sprint(h.net.Src())
	srcPort := fmt.Sprint(h.transport.Src())
	dstHost := fmt.Sprint(h.net.Dst())
	dstPort := fmt.Sprint(h.transport.Dst())
	
	// Track the last seen SASL Handshake mechanism
	lastSaslMechanism := ""

	// Simple connection log with source -> destination format
	log.Printf("%s:%s -> %s:%s", srcHost, srcPort, dstHost, dstPort)

	buf := bufio.NewReaderSize(&h.r, 2<<15) // 65k

	// add new client ip to metric
	h.metricsStorage.AddActiveConnectionsTotal(h.net.Src().String())

	for {
		// Try to peek at the next 16 bytes to check for raw SASL tokens after a SASL handshake
		if lastSaslMechanism == "PLAIN" {
			peekData, err := buf.Peek(16)
			if err == nil && len(peekData) >= 4 {
				// Check if this looks like a raw SASL token (not a Kafka protocol message)
				// Real Kafka messages start with a 4-byte length followed by API key, version, etc.
				// SASL tokens typically start with 0x00 for PLAIN mechanism
				msgSize := int(binary.BigEndian.Uint32(peekData[:4]))
				
				// If this is a small message and starts with a null byte, it might be a raw SASL token
				if msgSize < 1000 && len(peekData) > 4 && peekData[4] == 0 {
					// Read the full message
					tokenData := make([]byte, msgSize+4) // +4 for the length field
					_, err := io.ReadFull(buf, tokenData)
					if err == nil {
						// Attempt to extract username from the SASL token
						username, ok := extractSaslPlainUsername(tokenData[4:])
						if ok {
							log.Printf("Client: %s, Raw SASL Auth, Mechanism: %s, Username: %s", 
								srcHost, lastSaslMechanism, username)
							
							// Store the client address for this session
							h.clientAddress = h.net.Src().String() // Make sure clientAddress is set
							
							// Store username information for this stream
							h.currentUsername = username
							h.currentMechanism = lastSaslMechanism
							
							// Store in global auth tracker for use across connections
							kafkalog.StoreAuthHandshake(srcHost, lastSaslMechanism)
							kafkalog.UpdateAuthSession(srcHost, username)
							
							// Track metrics
							h.metricsStorage.AddActiveConnectionsTotal(fmt.Sprintf("%s:%s", srcHost, username))
							
							// Record the auth user in metrics and storage - critical for tracking
							metrics.RecordAuthUser(h.clientAddress, username, lastSaslMechanism)
							
							// Also directly add the user-client mapping in the metrics storage
							h.metricsStorage.AddUserClientMapping(h.clientAddress, username, lastSaslMechanism)
							
							// Update existing topic relationships with this username
							h.updateExistingTopicRelationships()
						}
						// Reset the last mechanism so we don't try to process raw tokens again
						lastSaslMechanism = ""
						continue
					}
				}
			}
		}
		// Proceed with decoding as usual
		req, readBytes, err := kafka.DecodeRequest(buf)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			log.Println("got EOF - stop reading from stream")
			return
		}

		if err != nil {
			// Skip detailed error logging

			if _, ok := err.(kafka.PacketDecodingError); ok {
				_, _ = buf.Discard(readBytes)
			}

			continue
		}

		// API name will be determined by getApiName function
		// No need for this switch statement as we have a complete mapping function
		/*
		switch req.Key {
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
		case 19:
			apiName = "CreateTopics"
		case 20:
			apiName = "DeleteTopics"
		case 36:
			apiName = "SaslAuthenticate"
		}
		*/
		// Print detailed request header information for all requests
		logRequestHeaderDetails(req, srcHost, srcPort, dstHost, dstPort)
		
		// Track SASL Handshake mechanism for raw token processing
		if req.Key == 17 { // SaslHandshake
			if handshakeReq, ok := req.Body.(*kafka.SaslHandshakeRequest); ok {
				lastSaslMechanism = handshakeReq.Mechanism
			}
		}
		
		// Process specific request types for topic tracking and authentication
		switch body := req.Body.(type) {
		case *kafka.ProduceRequest:
			for _, topic := range body.ExtractTopics() {
				// Log topic write access in both the standard format and the summary log
				// Log production activity

				// Set client address if not already set
				if h.clientAddress == "" {
					h.clientAddress = h.net.Src().String()
					// Set client address
				}

				// Add producer-topic relation to metrics
				h.metricsStorage.AddProducerTopicRelationInfo(h.clientAddress, topic)
				// Track producer-topic relationship
				
				// First check if we have a username in the current stream
				username := h.currentUsername
				// Check if we have username in current stream
				
				// If not, try to get it from the global auth tracker using base IP
				if username == "" {
					// Try base IP lookup first - most reliable
					baseUsername := kafkalog.GetUsernameByIP(h.clientAddress)
					if baseUsername != "" {
						username = baseUsername
						// Store this for future use
						h.currentUsername = username
					} else if session, found := kafka.GetAuthSession(srcHost); found && session.Username != "" {
						username = session.Username
						// Also update the current stream with this username for future use
						h.currentUsername = username
						h.currentMechanism = session.Mechanism
					} else {
						// No username found
					}
				}
				
				// Now update the metrics with the username (if found)
				if username != "" {
					metrics.ProducerUserTopicInfo.WithLabelValues(h.clientAddress, username, topic).Set(1)
				} else {
					// Log topic write access without username
					log.Printf("client %s produced to topic %s", srcHost, topic)
				}
				
				// Write to both standard logs and summary file
				summaryLogger := kafkalog.GetSummaryLogger()
				summaryLogger.LogTopicProduction(srcHost, srcPort, topic, username)
			}
		case *kafka.FetchRequest:
			for _, topic := range body.ExtractTopics() {
				// Log topic read access in the debug format
				// Client is consuming from topic

				// Set client address if not already set
				if h.clientAddress == "" {
					h.clientAddress = h.net.Src().String()
					// Set client address
				}

				// Add consumer-topic relation to metrics
				h.metricsStorage.AddConsumerTopicRelationInfo(h.clientAddress, topic)
				// Consumer-topic relation added
				
				// First check if we have a username in the current stream
				username := h.currentUsername
				
				// If not, try to get it from the global auth tracker
				if username == "" {
					// Try base IP lookup first - most reliable
					baseUsername := kafka.GetUsernameByIP(h.clientAddress)
					if baseUsername != "" {
						username = baseUsername
						// Store this for future use
						h.currentUsername = username
					} else if session, found := kafkalog.GetAuthSession(srcHost); found && session.Username != "" {
						username = session.Username
						// Also update the current stream with this username for future use
						h.currentUsername = username
						h.currentMechanism = session.Mechanism
					} else {
						// No username found
					}
				}
				
				// Now update the metrics with the username (if found)
				if username != "" {
					metrics.ConsumerUserTopicInfo.WithLabelValues(h.clientAddress, username, topic).Set(1)
				} else {
					// Log topic read access without username
					log.Printf("client %s consumed from topic %s", srcHost, topic)
				}
				
				// Write to both standard logs and summary file
				summaryLogger := kafkalog.GetSummaryLogger()
				summaryLogger.LogTopicConsumption(srcHost, srcPort, topic, username)
			}
		case *kafka.ListOffsetsRequest:
			for _, topic := range body.ExtractTopics() {
				// Log topic information queries
				log.Printf("client %s queried offsets for topic %s", srcHost, topic)
				// Add consumer-topic relation as this often precedes actual consumption
				h.metricsStorage.AddConsumerTopicRelationInfo(h.net.Src().String(), topic)
				
				// Directly update the user-topic metrics if we have a username
				if h.currentUsername != "" {
					metrics.ConsumerUserTopicInfo.WithLabelValues(h.clientAddress, h.currentUsername, topic).Set(1)
				}
			}
		case *kafka.MetadataRequest:
			for _, topic := range body.ExtractTopics() {
				// Only log actual topic names, not empty queries for all topics
				if topic != "" {
					log.Printf("client %s requested metadata for topic %s", srcHost, topic)
				}
			}
		case *kafka.SaslAuthenticateRequest:
			// Handle the SaslAuthenticate request (API key 36)
			// SASL authentication request received
			
			if body.Username != "" {
				// Authenticated username found
				
				// Store username for this stream
				h.clientAddress = h.net.Src().String() // Ensure clientAddress is set
				h.currentUsername = body.Username
				h.currentMechanism = body.Mechanism
				
				// Store authentication in the global auth tracker
				// This makes the username available for other connections from the same client
				kafkalog.StoreAuthHandshake(srcHost, body.Mechanism)
				kafkalog.UpdateAuthSession(srcHost, body.Username)
				
				// Directly track authentication in metrics
				metrics.AuthenticationInfo.WithLabelValues(h.clientAddress, h.currentMechanism, h.currentUsername).Inc()
				
				// Add user tracking in metrics
				metrics.TrackSaslAuthentication(h.clientAddress, h.currentMechanism, h.currentUsername)
				
				// Update existing topic relationships with this username
				h.updateExistingTopicRelationships()
			} else {
				// Empty username in SaslAuthenticateRequest
			}
		case *kafka.SaslHandshakeRequest:
			// Handle the SaslHandshake request (API key 17)
			// Skip detailed handshake logs
			h.currentMechanism = body.Mechanism
			
			// Store the handshake in the global auth tracker for later correlation
			// This helps with SASL authentication tracking
			kafka.StoreAuthHandshake(srcHost, body.Mechanism)
			
			// After a handshake, we should check if there's authentication data in the buffer
			// that might not be properly parsed as a SaslAuthenticate request
			h.tryExtractAuthData(buf, srcHost, body.Mechanism)
		}
	}
}

// updateExistingTopicRelationships updates existing topic relationships with username information
func (h *KafkaStream) updateExistingTopicRelationships() {
	// Verify we have a username and client address
	if h.currentUsername == "" || h.clientAddress == "" {
		// Try to get the username from the auth tracker if we don't have it locally
		if h.currentUsername == "" && h.clientAddress != "" {
			if session, found := kafka.GetAuthSession(h.clientAddress); found && session.Username != "" {
				h.currentUsername = session.Username
				h.currentMechanism = session.Mechanism
			}
		}
		
		// If we still don't have both, skip the update
		if h.currentUsername == "" || h.clientAddress == "" {
			return
		}
	}

	// Set client address if not already set
	if h.clientAddress == "" {
		h.clientAddress = h.net.Src().String()
		// Setting client address
		
		// Try to get username immediately after setting client address
		if h.currentUsername == "" {
			username := kafka.GetUsernameByIP(h.clientAddress)
			if username != "" {
				h.currentUsername = username
				// Associated username with client
			} else {
				// No username found during address setup
			}
		}
	}

	// Get topics this client has produced to
	producerTopics := h.metricsStorage.GetClientProducerTopics(h.clientAddress)
	// Found producer topics for client
	
	for _, topic := range producerTopics {
		// Updating producer topic relation
		metrics.ProducerUserTopicInfo.WithLabelValues(h.clientAddress, h.currentUsername, topic).Set(1)
	}

	// Get topics this client has consumed from
	consumerTopics := h.metricsStorage.GetClientConsumerTopics(h.clientAddress)
	// Found consumer topics for client
	
	for _, topic := range consumerTopics {
		// Updating consumer topic relation
		metrics.ConsumerUserTopicInfo.WithLabelValues(h.clientAddress, h.currentUsername, topic).Set(1)
	}

	// Finished updating topic relationships
}
