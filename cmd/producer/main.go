package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/Shopify/sarama"
)

var (
	brokers = flag.String("brokers", os.Getenv("KAFKA_PEERS"), "The Kafka brokers to connect to, as a comma separated list")
	// SASL authentication flags
	useSASL       = flag.Bool("sasl", false, "Use SASL authentication")
	saslMechanism = flag.String("sasl-mechanism", "PLAIN", "SASL mechanism to use (PLAIN, SCRAM-SHA-256, SCRAM-SHA-512)")
	saslUsername  = flag.String("sasl-username", "", "SASL username")
	saslPassword  = flag.String("sasl-password", "", "SASL password")
	// Topic flags
	topics        = flag.String("topics", "mytopic,mysecondtopic", "Comma-separated list of topics to produce to")
	sendInterval  = flag.Int("interval", 5, "Interval in seconds between message sends")
	clientID      = flag.String("client-id", "kafka-sniffer-producer", "Client ID to use for connections")
)

func main() {
	flag.Parse()

	sarama.Logger = log.New(os.Stdout, "[sarama] ", log.LstdFlags)

	if *brokers == "" {
		log.Println("No Kafka brokers specified. Please provide at least one broker.")
		flag.PrintDefaults()
		os.Exit(1)
	}

	if *useSASL && *saslUsername == "" {
		log.Println("SASL enabled but no username provided. Please specify a username.")
		flag.PrintDefaults()
		os.Exit(1)
	}

	brokerList := strings.Split(*brokers, ",")
	log.Printf("Kafka brokers: %s", strings.Join(brokerList, ", "))
	
	// Log authentication settings
	if *useSASL {
		log.Printf("Using SASL authentication with mechanism %s and username %s",
			*saslMechanism, *saslUsername)
	}

	topicList := strings.Split(*topics, ",")
	log.Printf("Will produce to topics: %s", strings.Join(topicList, ", "))

	producer, err := newDataCollector(brokerList)
	if err != nil {
		log.Fatalf("Failed to create producer: %v", err)
	}
	defer func() {
		if err := producer.Close(); err != nil {
			log.Printf("Failed to close producer: %v", err)
		}
	}()

	t := time.NewTicker(time.Duration(*sendInterval) * time.Second)

	for range t.C {
		// Create messages for all configured topics
		messages := make([]*sarama.ProducerMessage, 0, len(topicList))
		for _, topic := range topicList {
			messages = append(messages, &sarama.ProducerMessage{
				Topic: topic,
				Key:   sarama.StringEncoder(time.Now().Format(time.RFC3339)),
				Value: sarama.StringEncoder("message produced by kafka-sniffer test tool at " + time.Now().String()),
				Headers: []sarama.RecordHeader{
					{Key: []byte("producer"), Value: []byte("kafka-sniffer-test")},
					{Key: []byte("timestamp"), Value: []byte(time.Now().Format(time.RFC3339))},
				},
			})
		}

		// Send messages
		err := producer.SendMessages(messages)
		if err != nil {
			log.Printf("Failed to send messages: %s", err)
		} else {
			log.Printf("Successfully sent %d messages to topics: %s", 
				len(messages), strings.Join(topicList, ", "))
		}

		// Also trigger an API versions request to demonstrate client software detection
		// This doesn't actually send anything but helps the sniffer detect our client software
		// Create a new temporary config just for this API versions request
		apiConfig := sarama.NewConfig()
		apiConfig.ClientID = *clientID + "-" + fmt.Sprintf("%d", time.Now().Unix()%1000)
		if apiClient, err := sarama.NewClient(brokerList, apiConfig); err == nil {
			_ = apiClient.Close()
		}
	}
}

func newDataCollector(brokerList []string) (sarama.SyncProducer, error) {

	// For the data collector, we are looking for strong consistency semantics.
	// Because we don't change the flush settings, sarama will try to produce messages
	// as fast as possible to keep latency low.
	config := sarama.NewConfig()

	// Let Sarama use version negotiation to automatically select the highest supported version
	// This will ensure we use the latest Produce API version that both the client and server support
	config.Version = sarama.MaxVersion
	log.Printf("Using highest supported Kafka version: %s", config.Version)
	config.Producer.Return.Successes = true
	config.Producer.Return.Errors = true
	
	// Configure SASL if enabled
	if *useSASL {
		config.Net.SASL.Enable = true
		config.Net.SASL.User = *saslUsername
		config.Net.SASL.Password = *saslPassword
		
		switch *saslMechanism {
		case "PLAIN":
			config.Net.SASL.Mechanism = sarama.SASLTypePlaintext
		case "SCRAM-SHA-256":
			config.Net.SASL.Mechanism = sarama.SASLTypeSCRAMSHA256
		case "SCRAM-SHA-512":
			config.Net.SASL.Mechanism = sarama.SASLTypeSCRAMSHA512
		default:
			log.Fatalf("Unsupported SASL mechanism: %s", *saslMechanism)
		}
	}

	producer, err := sarama.NewSyncProducer(brokerList, config)
	if err != nil {
		return nil, fmt.Errorf("failed to start Sarama producer: %w", err)
	}

	return producer, nil
}
