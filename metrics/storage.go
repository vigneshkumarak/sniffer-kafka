package metrics

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const namespace = "kafka_sniffer"

// Storage contains prometheus metrics that have expiration time. When expiration time is exceeded,
// metric with specific labels is removed from storage. It is needed to keep only fresh producer,
// topic and consumer relations.
type Storage struct {
	producerTopicRelationInfo *metric
	consumerTopicRelationInfo *metric
	activeConnectionsTotal    *metric
	
	// Maps client IPs to their authenticated usernames
	userClientMapping     map[string]userInfo
	// Maps client IPs to the topics they produce to
	clientProducerTopics  map[string]map[string]bool
	// Maps client IPs to the topics they consume from
	clientConsumerTopics  map[string]map[string]bool
	// Mutex for thread-safe map access
	mapMutex              sync.RWMutex
}

// userInfo stores authentication information for a client
type userInfo struct {
	username   string
	mechanism  string
	lastActive time.Time
}

// NewStorage creates new Storage
func NewStorage(registerer prometheus.Registerer, expireTime time.Duration) *Storage {
	var s = &Storage{
		producerTopicRelationInfo: newMetric(prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "producer_topic_relation_info",
			Help:      "Relation information between producer and topic",
		}, []string{"client_ip", "topic"}), expireTime),
		consumerTopicRelationInfo: newMetric(prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "consumer_topic_relation_info",
			Help:      "Relation information between consumer and topic",
		}, []string{"client_ip", "topic"}), expireTime),
		activeConnectionsTotal: newMetric(prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "active_connections_total",
			Help:      "Contains total count of active connections",
		}, []string{"client_ip"}), expireTime),
		userClientMapping:     make(map[string]userInfo),
		clientProducerTopics:  make(map[string]map[string]bool),
		clientConsumerTopics:  make(map[string]map[string]bool),
	}

	// Use safe registration approach for all metrics to avoid panics on duplicate registration
	tryRegister := func(c prometheus.Collector) {
		if err := registerer.Register(c); err != nil {
			fmt.Printf("Note: metric already registered: %v\n", err)
		}
	}
	
	// First register storage-specific metrics
	tryRegister(s.producerTopicRelationInfo.promMetric)
	tryRegister(s.consumerTopicRelationInfo.promMetric)
	tryRegister(s.activeConnectionsTotal.promMetric)
	
	// Then register the global metrics from external.go
	
	tryRegister(RequestsCount)
	tryRegister(ProducerBatchLen)
	tryRegister(ProducerBatchSize)
	tryRegister(BlocksRequested)
	tryRegister(ClientSoftwareInfo)
	tryRegister(AuthenticationInfo)
	tryRegister(AuthUserActivity) 
	tryRegister(ProducerUserTopicInfo)
	tryRegister(ConsumerUserTopicInfo)

	return s
}

// AddProducerTopicRelationInfo adds (producer, topic) pair to metrics
func (s *Storage) AddProducerTopicRelationInfo(producer, topic string) {
	s.producerTopicRelationInfo.set(producer, topic)
	
	// Track producer -> topic relationship in memory
	s.mapMutex.Lock()
	defer s.mapMutex.Unlock()
	
	if _, exists := s.clientProducerTopics[producer]; !exists {
		s.clientProducerTopics[producer] = make(map[string]bool)
	}
	s.clientProducerTopics[producer][topic] = true
	
	// If this client has an associated username, also update the user-topic metrics
	if userInfo, exists := s.userClientMapping[producer]; exists {
		// Update the metric to track which user is producing to this topic
		ProducerUserTopicInfo.WithLabelValues(producer, userInfo.username, topic).Set(1)
		fmt.Printf("Storage: Updated producer-topic relation with username: %s -> %s (user: %s)\n", 
			producer, topic, userInfo.username)
	}
}

// AddConsumerTopicRelationInfo adds (consumer, topic) pair to metrics
func (s *Storage) AddConsumerTopicRelationInfo(consumer, topic string) {
	s.consumerTopicRelationInfo.set(consumer, topic)
	
	// Track consumer -> topic relationship in memory
	s.mapMutex.Lock()
	defer s.mapMutex.Unlock()
	
	if _, exists := s.clientConsumerTopics[consumer]; !exists {
		s.clientConsumerTopics[consumer] = make(map[string]bool)
	}
	s.clientConsumerTopics[consumer][topic] = true
	
	// If this client has an associated username, also update the user-topic metrics
	if userInfo, exists := s.userClientMapping[consumer]; exists {
		// Update the metric to track which user is consuming from this topic
		ConsumerUserTopicInfo.WithLabelValues(consumer, userInfo.username, topic).Set(1)
		fmt.Printf("Storage: Updated consumer-topic relation with username: %s -> %s (user: %s)\n", 
			consumer, topic, userInfo.username)
	}
}

// AddActiveConnectionsTotal adds incoming connection
func (s *Storage) AddActiveConnectionsTotal(clientIP string) {
	s.activeConnectionsTotal.inc(clientIP)
}

// AddUserClientMapping associates a username with a client IP
func (s *Storage) AddUserClientMapping(clientIP, username, mechanism string) {
	s.mapMutex.Lock()
	defer s.mapMutex.Unlock()
	
	// Store the username and authentication info for this client IP
	s.userClientMapping[clientIP] = userInfo{
		username:   username,
		mechanism:  mechanism,
		lastActive: time.Now(),
	}
	
	// Also update the user-topic metrics for any existing topic relationships
	s.updateUserTopicMetrics(clientIP, username)
	
	fmt.Printf("Storage: Added user mapping for client %s, username %s, mechanism %s\n", 
		clientIP, username, mechanism)
}

// GetUsernameForClient returns the username associated with a client IP
func (s *Storage) GetUsernameForClient(clientIP string) string {
	s.mapMutex.RLock()
	defer s.mapMutex.RUnlock()
	
	userData, exists := s.userClientMapping[clientIP]
	if !exists {
		return ""
	}
	
	// Update last active time
	userData.lastActive = time.Now()
	s.userClientMapping[clientIP] = userData
	
	return userData.username
}

// GetAuthMechanismForClient returns the SASL mechanism used by a client
func (s *Storage) GetAuthMechanismForClient(clientIP string) string {
	s.mapMutex.RLock()
	defer s.mapMutex.RUnlock()
	
	userData, exists := s.userClientMapping[clientIP]
	if !exists {
		return ""
	}
	
	return userData.mechanism
}

// GetClientProducerTopics returns the list of topics a client is producing to
func (s *Storage) GetClientProducerTopics(clientIP string) []string {
	s.mapMutex.RLock()
	defer s.mapMutex.RUnlock()
	
	topics := []string{}
	for topic := range s.clientProducerTopics[clientIP] {
		topics = append(topics, topic)
	}
	return topics
}

// GetClientConsumerTopics returns the list of topics a client is consuming from
func (s *Storage) GetClientConsumerTopics(clientIP string) []string {
	s.mapMutex.RLock()
	defer s.mapMutex.RUnlock()
	
	topics := []string{}
	for topic := range s.clientConsumerTopics[clientIP] {
		topics = append(topics, topic)
	}
	return topics
}

// updateUserTopicMetrics updates all topic metrics with the username
// Should be called with the lock held
func (s *Storage) updateUserTopicMetrics(clientIP, username string) {
	// Update producer topic metrics
	for topic := range s.clientProducerTopics[clientIP] {
		ProducerUserTopicInfo.WithLabelValues(clientIP, username, topic).Set(1)
		fmt.Printf("Storage: Updated existing producer-topic relation with username: %s -> %s (user: %s)\n", 
			clientIP, topic, username)
	}
	
	// Update consumer topic metrics
	for topic := range s.clientConsumerTopics[clientIP] {
		ConsumerUserTopicInfo.WithLabelValues(clientIP, username, topic).Set(1)
		fmt.Printf("Storage: Updated existing consumer-topic relation with username: %s -> %s (user: %s)\n", 
			clientIP, topic, username)
	}
}

// CleanupExpiredUserMappings removes inactive user mappings to prevent memory leaks
func (s *Storage) CleanupExpiredUserMappings(expirationTime time.Duration) {
	s.mapMutex.Lock()
	defer s.mapMutex.Unlock()
	
	now := time.Now()
	for clientIP, userInfo := range s.userClientMapping {
		if now.Sub(userInfo.lastActive) > expirationTime {
			fmt.Printf("Storage: Removing expired user mapping for client %s, username %s\n", 
				clientIP, userInfo.username)
			delete(s.userClientMapping, clientIP)
		}
	}
}

// metric contains expiration functionality
type metric struct {
	promMetric *prometheus.GaugeVec
	expireTime time.Duration

	expCh chan []string

	mux       sync.Mutex
	relations map[string]*relation
}

func newMetric(promMetric *prometheus.GaugeVec, expireTime time.Duration) *metric {
	m := &metric{
		promMetric: promMetric,
		expireTime: expireTime,

		relations: make(map[string]*relation),
		expCh:     make(chan []string),
	}

	go m.runExpiration()

	return m
}

func (m *metric) set(labels ...string) {
	m.promMetric.WithLabelValues(labels...).Set(float64(1))

	m.update(labels...)
}

func (m *metric) inc(labels ...string) {
	m.promMetric.WithLabelValues(labels...).Inc()

	m.update(labels...)
}

// update updates relations or creates new one
func (m *metric) update(labels ...string) {
	m.mux.Lock()
	defer m.mux.Unlock()
	if r, ok := m.relations[genLabelKey(labels...)]; ok {
		r.refresh()
	} else {
		m.relations[genLabelKey(labels...)] = newRelation(m.expireTime, labels, m.expCh)
	}
}

// runExpiration removes metric by specific label values and removes relation
func (m *metric) runExpiration() {
	for labels := range m.expCh {
		m.promMetric.DeleteLabelValues(labels...)

		// remove relation
		m.mux.Lock()
		delete(m.relations, genLabelKey(labels...))
		m.mux.Unlock()
	}
}

// relation contains metric labels and expiration time
type relation struct {
	expireTime time.Duration

	labels []string
	expCh  chan []string

	mux   sync.Mutex
	timer *time.Timer
}

func newRelation(expireTime time.Duration, labels []string, expCh chan []string) *relation {
	var rel = relation{
		expireTime: expireTime,
		labels:     labels,
		expCh:      expCh,
	}

	go rel.run()

	return &rel
}

// run runs expiration with specific timer
func (c *relation) run() {
	c.refresh()

	<-c.timer.C
	c.expCh <- c.labels
}

// refresh resets timer or create new one
func (c *relation) refresh() {
	c.mux.Lock()
	defer c.mux.Unlock()
	if c.timer == nil {
		c.timer = time.NewTimer(c.expireTime)
	} else {
		c.timer.Reset(c.expireTime)
	}
}

func genLabelKey(labels ...string) string {
	return strings.Join(labels, "_")
}
