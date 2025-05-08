package metrics

import (
	"fmt"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	// RequestsCount is a prometheus metric. See info field
	RequestsCount = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "typed_requests_total",
		Help:      "Total requests to kafka by type and version",
	}, []string{"client_ip", "request_type", "version"})

	// ProducerBatchLen is a prometheus metric. See info field
	ProducerBatchLen = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "producer_batch_length",
		Help:      "Length of producer request batch to kafka",
	}, []string{"client_ip"})

	// ProducerBatchSize is a prometheus metric. See info field
	ProducerBatchSize = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "producer_batch_size",
		Help:      "Total size of a batch in producer request to kafka",
	}, []string{"client_ip"})

	// BlocksRequested is a prometheus metric. See info field
	BlocksRequested = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "blocks_requested",
		Help:      "Total size of a batch in producer request to kafka",
	}, []string{"client_ip"})

	// ClientSoftwareInfo is a prometheus metric for tracking client software information
	ClientSoftwareInfo = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "client_software_info",
		Help:      "Information about client software connecting to Kafka",
	}, []string{"client_ip", "software_name", "software_version"})

	// AuthenticationInfo is a prometheus metric for tracking client authentication
	AuthenticationInfo = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "authentication_info",
		Help:      "Information about client authentication to Kafka",
	}, []string{"client_ip", "mechanism", "username"})

	// AuthUserActivity tracks authentication events by username
	AuthUserActivity = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "auth_user_activity",
		Help:      "Activity tracking for authenticated users",
	}, []string{"client_ip", "username", "mechanism"})

	// ProducerUserTopicInfo tracks which users are producing to which topics
	ProducerUserTopicInfo = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "producer_user_topic_info",
		Help:      "Relationship between user, client and produced topics",
	}, []string{"client_ip", "username", "topic"})

	// ConsumerUserTopicInfo tracks which users are consuming from which topics
	ConsumerUserTopicInfo = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "consumer_user_topic_info",
		Help:      "Relationship between user, client and consumed topics",
	}, []string{"client_ip", "username", "topic"})

	// RequestVersionInfo tracks API versions used by clients
	RequestVersionInfo = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "request_version_info",
		Help:      "API versions used by clients for different request types",
	}, []string{"client_ip", "request_type", "version"})

	// ApiVersionByRequestType tracks API versions by request type and client
	ApiVersionByRequestType = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "api_version_by_request_type",
		Help:      "API versions used by clients for different request types and clients",
	}, []string{"client_ip", "request_type", "version"})
)

// InitializeMetrics initializes the metrics with zero values so they appear in the metrics endpoint
// This is separate from registration which happens in main via NewStorage
// This prevents duplicate registration errors
func InitializeMetrics() {
	fmt.Println("Initializing metrics with zero values...")
	
	// Initialize auth metrics
	AuthUserActivity.WithLabelValues("init", "init", "init").Set(0)
	
	// Initialize producer metrics
	ProducerUserTopicInfo.WithLabelValues("init", "init", "init").Set(0)
	
	// Initialize consumer metrics
	ConsumerUserTopicInfo.WithLabelValues("init", "init", "init").Set(0)
	
	// Initialize version metrics
	RequestVersionInfo.WithLabelValues("init", "init", "0").Set(0)
	ApiVersionByRequestType.WithLabelValues("init", "init", "0").Set(0)
	
	fmt.Println("Metrics initialization complete.")
}

func init() {
	// We'll just initialize the metrics but NOT register them
	// The registration is done in the main application via NewStorage
	// This prevents duplicate registration errors
	InitializeMetrics()
}

// ClientMetricsCollector is an interface, which allows to collect metrics for concrete client
type ClientMetricsCollector interface {
	CollectClientMetrics(srcHost string)
}
