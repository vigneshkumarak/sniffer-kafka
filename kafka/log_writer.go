package kafka

import (
	"fmt"
	"log"
	"os"
	"sync"
	"time"
)

var (
	// Default logger to a separate file for important events
	summaryLogger *SummaryLogger
	once          sync.Once
)

// SummaryLogger manages writing important events to a separate file
type SummaryLogger struct {
	file   *os.File
	logger *log.Logger
	mu     sync.Mutex
}

// GetSummaryLogger returns a singleton instance of the summary logger
func GetSummaryLogger() *SummaryLogger {
	once.Do(func() {
		// Create the summary file
		file, err := os.OpenFile("kafka_activity_summary.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			log.Printf("Failed to open summary log file: %v", err)
			return
		}
		
		summaryLogger = &SummaryLogger{
			file:   file,
			logger: log.New(file, "", log.LstdFlags),
		}
	})
	return summaryLogger
}

// LogAuthentication logs SASL authentication events to both standard log and summary
func (sl *SummaryLogger) LogAuthentication(clientIP, mechanism, username string) {
	if sl == nil || sl.logger == nil {
		return
	}
	
	message := fmt.Sprintf("Client: %s, Auth: %s, Username: %s", clientIP, mechanism, username)
	
	// Standard log using the normal logger
	log.Printf("Client: %s, Raw SASL Auth, Mechanism: %s, Username: %s", clientIP, mechanism, username)
	
	// Also log to summary file
	sl.mu.Lock()
	defer sl.mu.Unlock()
	sl.logger.Println(message)
}

// LogTopicProduction logs produce events to both standard log and summary
func (sl *SummaryLogger) LogTopicProduction(clientIP, clientPort, topic, username string) {
	if sl == nil || sl.logger == nil {
		return
	}
	
	// Format timestamp ourselves to match existing log format
	timestamp := time.Now().Format("2006/01/02 15:04:05")
	
	userInfo := ""
	if username != "" {
		userInfo = fmt.Sprintf(" (user: %s)", username)
	}
	
	message := fmt.Sprintf("%s PRODUCE: %s:%s -> topic: %s%s", 
		timestamp, clientIP, clientPort, topic, userInfo)
	
	// Standard logs using the normal logger
	log.Printf("client %s wrote to topic %s", clientIP, topic)
	log.Printf("client %s:%s wrote to topic %s", clientIP, clientPort, topic)
	
	// Also log to summary file
	sl.mu.Lock()
	defer sl.mu.Unlock()
	sl.logger.Println(message)
}

// LogTopicConsumption logs consume events to both standard log and summary
func (sl *SummaryLogger) LogTopicConsumption(clientIP, clientPort, topic, username string) {
	if sl == nil || sl.logger == nil {
		return
	}
	
	// Format timestamp ourselves to match existing log format
	timestamp := time.Now().Format("2006/01/02 15:04:05")
	
	userInfo := ""
	if username != "" {
		userInfo = fmt.Sprintf(" (user: %s)", username)
	}
	
	message := fmt.Sprintf("%s CONSUME: %s:%s <- topic: %s%s", 
		timestamp, clientIP, clientPort, topic, userInfo)
	
	// Standard logs using the normal logger
	log.Printf("client %s read from topic %s", clientIP, topic)
	log.Printf("client %s:%s read from topic %s", clientIP, clientPort, topic)
	
	// Also log to summary file
	sl.mu.Lock()
	defer sl.mu.Unlock()
	sl.logger.Println(message)
}

// Close safely closes the summary log file
func (sl *SummaryLogger) Close() error {
	if sl == nil || sl.file == nil {
		return nil
	}
	
	sl.mu.Lock()
	defer sl.mu.Unlock()
	return sl.file.Close()
}
