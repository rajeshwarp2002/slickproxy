package ipblocker

import (
	"log"
	"os/exec"
	"slickproxy/internal/config"
	"sync"
	"time"
)

const chainName = "SLICKPROXY_BLOCKED"

// IPBlocker manages authentication failures and iptables-based IP blocking
// Simple design: track failure counts, every 5 minutes block IPs that crossed threshold
type IPBlocker struct {
	// Runtime state - single map for IP failure counts
	failureCounts map[string]int // IP -> failure count in current 5-min window
	mu            sync.RWMutex

	// Config
	FailureThreshold int           // failures needed to trigger block
	BlockDuration    time.Duration // how long to block (5 minutes default)
}

// NewIPBlocker creates a new IP blocker with settings from config
// Defaults: FailureThreshold=100, BlockDuration=5 minutes
// Returns nil if IP blocking is disabled in config
func NewIPBlocker() *IPBlocker {
	// Check if IP blocking is enabled
	if config.Cfg != nil && !config.Cfg.IPBlocking.Enabled {
		log.Println("IP blocking is disabled in config")
		return nil
	}

	// Get threshold from config, default to 100
	threshold := 100
	if config.Cfg != nil && config.Cfg.IPBlocking.FailureThreshold > 0 {
		threshold = config.Cfg.IPBlocking.FailureThreshold
	}

	// Get block duration from config, default to 5 minutes
	blockDurationMin := 5
	if config.Cfg != nil && config.Cfg.IPBlocking.BlockDurationMin > 0 {
		blockDurationMin = config.Cfg.IPBlocking.BlockDurationMin
	}

	blocker := &IPBlocker{
		failureCounts:    make(map[string]int),
		FailureThreshold: threshold,
		BlockDuration:    time.Duration(blockDurationMin) * time.Minute,
	}

	log.Printf("IPBlocker initialized: threshold=%d failures, duration=%d minutes", threshold, blockDurationMin)

	// Initialize iptables chain
	blocker.initializeChain()

	// Start blocking/cleanup cycle
	go blocker.startBlockingCycle()

	return blocker
}

// TrackAuthFailure records an authentication failure for an IP
// Checks if entry exists with RLock, then uses Lock to create or increment
func (b *IPBlocker) TrackAuthFailure(clientIP string) {
	// First check if entry exists with RLock
	b.mu.RLock()
	_, exists := b.failureCounts[clientIP]
	if exists {
		// If it exists, we can increment it safely with RLock (since map value is int)
		b.failureCounts[clientIP]++
	}
	b.mu.RUnlock()

	// Then take write lock to create or increment

	if !exists {
		b.mu.Lock()
		// Entry doesn't exist, create it
		b.failureCounts[clientIP] = 1
		b.mu.Unlock()
	}
}

// startBlockingCycle runs every 5 minutes to block/unblock IPs based on failure counts
func (b *IPBlocker) startBlockingCycle() {
	ticker := time.NewTicker(b.BlockDuration)
	defer ticker.Stop()

	for range ticker.C {
		b.processCycle()
	}
}

// processCycle handles the 5-minute blocking cycle:
// 1. Clear all existing iptables rules
// 2. Check failure counts and add rules for IPs that crossed threshold
// 3. Clear the failure counts for next cycle
func (b *IPBlocker) processCycle() {
	// Step 1: Read failure counts with RLock
	b.mu.RLock()
	failureCounts := make(map[string]int)
	for ip, count := range b.failureCounts {
		failureCounts[ip] = count
	}
	b.mu.RUnlock()

	// Step 2: Clear all existing blocked_ rules
	b.clearAllBlockedRules()

	// Step 3: Add rules for IPs that crossed threshold
	blockedIPs := []string{}
	for ip, count := range failureCounts {
		if count >= b.FailureThreshold {
			b.addIPTablesRule(ip)
			blockedIPs = append(blockedIPs, ip)
		}
	}

	// Step 4: Clear the failure counts for next cycle with write lock
	b.mu.Lock()
	b.failureCounts = make(map[string]int)
	b.mu.Unlock()

	log.Printf("Blocking cycle completed: %d IPs checked, threshold=%d, blocked IPs: %v", len(failureCounts), b.FailureThreshold, blockedIPs)
}

// initializeChain creates the custom iptables chain if it doesn't exist
func (b *IPBlocker) initializeChain() {
	// Try to create the chain (will fail if it already exists, which is fine)
	cmd := exec.Command("iptables", "-N", chainName)
	cmd.Run() // Ignore error if chain already exists

	// Add jump rule from INPUT to our chain (at position 1)
	cmd = exec.Command("iptables", "-I", "INPUT", "1", "-j", chainName)
	if err := cmd.Run(); err != nil {
		log.Printf("Warning: could not add INPUT jump rule: %v", err)
	}

	log.Printf("Iptables chain %s initialized", chainName)
}

// clearAllBlockedRules flushes all rules from the custom chain
func (b *IPBlocker) clearAllBlockedRules() {
	cmd := exec.Command("iptables", "-F", chainName)
	if err := cmd.Run(); err != nil {
		log.Printf("Error flushing iptables chain %s: %v", chainName, err)
		return
	}

	log.Printf("Flushed iptables chain %s", chainName)
}

// addIPTablesRule adds a DROP rule for the specified IP to the custom chain
func (b *IPBlocker) addIPTablesRule(ip string) {
	cmd := exec.Command("iptables",
		"-I", chainName, "1",
		"-s", ip,
		"-j", "DROP",
	)

	if err := cmd.Run(); err != nil {
		log.Printf("Error adding iptables rule for IP %s: %v", ip, err)
		return
	}

	log.Printf("Blocked IP %s (failures in window >= %d)", ip, b.FailureThreshold)
}

// GetStats returns current blocking statistics (for monitoring)
func (b *IPBlocker) GetStats() map[string]interface{} {
	b.mu.RLock()
	defer b.mu.RUnlock()

	return map[string]interface{}{
		"tracked_ips":       len(b.failureCounts),
		"failure_threshold": b.FailureThreshold,
		"block_duration":    b.BlockDuration.String(),
	}
}
