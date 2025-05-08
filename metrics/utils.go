package metrics

import (
	"fmt"
	"sync"
	"time"
)

type userMapping struct {
	username string
	mechanism string
	lastSeen time.Time
}

var (
	defaultStorage *Storage
	once           sync.Once
	clientUserMap  = make(map[string]*userMapping) // Maps client IPs to usernames
	clientUserMutex sync.RWMutex                  // Protects the map
)

// No automatic initialization here - main.go will initialize and set the storage
// This was causing a duplicate registration error

// AddProducerTopicRelationInfo adds producer-topic relation to the default metrics storage
func AddProducerTopicRelationInfo(producer, topic string) {
	if defaultStorage != nil {
		defaultStorage.AddProducerTopicRelationInfo(producer, topic)
	}
	
	// Also record with username information if available
	RecordProducerUserTopic(producer, topic)
}

// AddConsumerTopicRelationInfo adds consumer-topic relation to the default metrics storage
func AddConsumerTopicRelationInfo(consumer, topic string) {
	if defaultStorage != nil {
		defaultStorage.AddConsumerTopicRelationInfo(consumer, topic)
	}
	
	// Also record with username information if available
	RecordConsumerUserTopic(consumer, topic)
}

// AddActiveTopicInfo adds general topic information to metrics
// This is used for metadata and other requests that don't clearly indicate producer/consumer
func AddActiveTopicInfo(clientIP, topic string) {
	if defaultStorage != nil {
		// For metadata requests, we don't know if client is producer or consumer
		// so we record both to indicate activity
		defaultStorage.AddProducerTopicRelationInfo(clientIP, topic)
		defaultStorage.AddConsumerTopicRelationInfo(clientIP, topic)
	}
}

// SetDefaultStorage sets the default metrics storage for utility functions
func SetDefaultStorage(storage *Storage) {
	once.Do(func() {
		defaultStorage = storage
	})
}

// RecordAuthUser records authenticated user activity
func RecordAuthUser(clientIP, username, mechanism string) {
	if username == "" {
		return // Skip empty usernames
	}
	
	// Recording auth user
	
	// Record the authentication in metrics
	AuthUserActivity.WithLabelValues(clientIP, username, mechanism).Set(1)
	
	// Save username to clientIP mapping for future use
	setClientUser(clientIP, username, mechanism)
	// Saved username for client
	
	// Update any existing topic relationships with the username
	updateTopicRelationshipsWithUsername(clientIP, username)
}

// RecordProducerUserTopic records a producer-topic relation with username
func RecordProducerUserTopic(clientIP, topic string) {
	username := getClientUser(clientIP)
	if username != "" {
		// Recording producer topic relation
		ProducerUserTopicInfo.WithLabelValues(clientIP, username, topic).Set(1)
	} else {
		// No username found for client when recording producer topic
	}
}

// RecordConsumerUserTopic records a consumer-topic relation with username
func RecordConsumerUserTopic(clientIP, topic string) {
	username := getClientUser(clientIP)
	if username != "" {
		// Recording consumer topic relation
		ConsumerUserTopicInfo.WithLabelValues(clientIP, username, topic).Set(1)
	} else {
		// No username found for client when recording consumer topic
	}
}

// updateTopicRelationshipsWithUsername updates existing topic relationships
// with the username information when a new authentication is detected
func updateTopicRelationshipsWithUsername(clientIP, username string) {
	if defaultStorage == nil {
		return
	}
	
	// Get any existing topic relationships for this client and update them with username
	producerTopics := defaultStorage.GetClientProducerTopics(clientIP)
	for _, topic := range producerTopics {
		ProducerUserTopicInfo.WithLabelValues(clientIP, username, topic).Set(1)
	}
	
	consumerTopics := defaultStorage.GetClientConsumerTopics(clientIP)
	for _, topic := range consumerTopics {
		ConsumerUserTopicInfo.WithLabelValues(clientIP, username, topic).Set(1)
	}
}

// setClientUser stores a username for a client IP address
func setClientUser(clientIP, username, mechanism string) {
	clientUserMutex.Lock()
	defer clientUserMutex.Unlock()
	clientUserMap[clientIP] = &userMapping{
		username: username,
		mechanism: mechanism,
		lastSeen: time.Now(),
	}
}

// getClientUser retrieves a username for a client IP address
func getClientUser(clientIP string) string {
	clientUserMutex.RLock()
	defer clientUserMutex.RUnlock()
	
	if mapping, exists := clientUserMap[clientIP]; exists {
		// Update last seen time
		mapping.lastSeen = time.Now()
		return mapping.username
	}
	return ""
}

// CleanupExpiredUserMappings removes old client->username mappings
// Call this function in a goroutine
func CleanupExpiredUserMappings() {
	for {
		time.Sleep(5 * time.Minute)
		clientUserMutex.Lock()
		now := time.Now()
		for clientIP, mapping := range clientUserMap {
			if now.Sub(mapping.lastSeen) > 30*time.Minute {
				delete(clientUserMap, clientIP)
			}
		}
		clientUserMutex.Unlock()
	}
}

// TrackSaslAuthentication tracks authentication metrics for SASL connections
func TrackSaslAuthentication(clientIP, mechanism, username string) {
	fmt.Printf("DEBUG: TrackSaslAuthentication called for client=%s, mechanism=%s, username=%s\n", 
		clientIP, mechanism, username)
	
	// Track in the authentication metrics
	if mechanism != "" {
		// Record authentication info in the metrics
		// The username field may be empty for the initial SASL handshake
		AuthenticationInfo.WithLabelValues(clientIP, mechanism, username).Inc()
		fmt.Println("DEBUG: Recorded authentication info in metrics")
		
		// Record authenticated user activity
		RecordAuthUser(clientIP, username, mechanism)
		
		// If we have a username, track active connection
		if username != "" && defaultStorage != nil {
			// Track active connection for this client
			defaultStorage.AddActiveConnectionsTotal(clientIP)
			fmt.Printf("DEBUG: Added active connection for client %s\n", clientIP)
		} else {
			fmt.Printf("DEBUG: Skip adding active connection - username empty or defaultStorage nil (username empty: %v, defaultStorage nil: %v)\n", 
				username == "", defaultStorage == nil)
		}
	} else {
		fmt.Println("DEBUG: Skipping auth tracking - mechanism is empty")
	}
}
