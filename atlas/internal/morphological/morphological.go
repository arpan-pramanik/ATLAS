// Package morphological implements the Morphological State Engine for ATLAS.
// It maintains a sliding window of connection records and computes real-time
// metrics including fingerprint uniqueness, feature-space entropy, and
// connection health statistics that drive the adaptive controller.
package morphological

import (
	"math"
	"sync"
	"time"
)

// ConnectionRecord captures telemetry for a single TLS connection.
type ConnectionRecord struct {
	Timestamp       time.Time     // When the connection was initiated.
	ProfileID       string        // Which TLS profile was used.
	FingerprintHash string        // JA3 hash of the resulting ClientHello.
	JA4Hash         string        // JA4-like hash of the resulting ClientHello.
	HandshakeRTT    time.Duration // Time to complete the TLS handshake.
	Success         bool          // Whether the handshake succeeded.
	Generation      int           // Genome generation number at time of connection.
}

// Metrics holds all computed metrics from the state engine at a point in time.
type Metrics struct {
	// JA3 Uniqueness Index: U_F = 1 - max_count(hash) / N
	// Higher is better (more unique). Range [0, 1].
	JA3UniquenessIndex float64

	// JA4 Uniqueness Index, same formula as JA3 but for JA4 hashes.
	JA4UniquenessIndex float64

	// Normalized Shannon entropy of cipher suite distribution across connections.
	// H'(X) = H(X) / log2(|X|), range [0, 1].
	CipherEntropy float64

	// Normalized Shannon entropy of profile ID distribution.
	ProfileEntropy float64

	// Normalized Shannon entropy of fingerprint hash distribution.
	FingerprintEntropy float64

	// Fingerprint Variance Score: estimated from fingerprint diversity.
	// C = min(1.0, (unique_hashes / n) * 2)
	VarianceScore float64

	// Median handshake latency over the window.
	MedianLatency time.Duration

	// Mean handshake latency over the window.
	MeanLatency time.Duration

	// Connection failure rate (0.0 to 1.0).
	FailureRate float64

	// Total connections in the current window.
	WindowSize int

	// Per-profile reuse counts within the window.
	ProfileReuseCounts map[string]int

	// Per-profile failure rates.
	ProfileFailureRates map[string]float64

	// Per-profile mean latencies.
	ProfileMeanLatencies map[string]time.Duration
}

// StateEngine maintains the sliding window and computes real-time metrics.
type StateEngine struct {
	mu         sync.RWMutex
	windowSize int                 // Maximum number of records in the window.
	records    []ConnectionRecord  // Ring buffer of connection records.
	head       int                 // Next write position in the ring buffer.
	count      int                 // Current number of records in the buffer.
}

// NewStateEngine creates a new state engine with the given sliding window size.
func NewStateEngine(windowSize int) *StateEngine {
	if windowSize <= 0 {
		windowSize = 100
	}
	return &StateEngine{
		windowSize: windowSize,
		records:    make([]ConnectionRecord, windowSize),
	}
}

// RecordConnection adds a new connection record to the sliding window.
func (s *StateEngine) RecordConnection(record ConnectionRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.records[s.head] = record
	s.head = (s.head + 1) % s.windowSize
	if s.count < s.windowSize {
		s.count++
	}
}

// GetMetrics computes and returns all current metrics from the sliding window.
func (s *StateEngine) GetMetrics() Metrics {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.count == 0 {
		return Metrics{
			JA3UniquenessIndex:   1.0,
			JA4UniquenessIndex:   1.0,
			VarianceScore:        1.0,
			ProfileReuseCounts:   make(map[string]int),
			ProfileFailureRates:  make(map[string]float64),
			ProfileMeanLatencies: make(map[string]time.Duration),
		}
	}

	records := s.activeRecords()
	n := len(records)

	metrics := Metrics{
		WindowSize:           n,
		ProfileReuseCounts:   make(map[string]int),
		ProfileFailureRates:  make(map[string]float64),
		ProfileMeanLatencies: make(map[string]time.Duration),
	}

	// Count fingerprint hashes, profiles, and cipher distributions.
	ja3Counts := make(map[string]int)
	ja4Counts := make(map[string]int)
	profileCounts := make(map[string]int)
	profileFailures := make(map[string]int)
	profileLatencySum := make(map[string]time.Duration)
	profileLatencyCount := make(map[string]int)

	var latencies []time.Duration
	var totalLatency time.Duration
	var failures int

	for _, rec := range records {
		ja3Counts[rec.FingerprintHash]++
		ja4Counts[rec.JA4Hash]++
		profileCounts[rec.ProfileID]++

		if rec.Success {
			latencies = append(latencies, rec.HandshakeRTT)
			totalLatency += rec.HandshakeRTT
			profileLatencySum[rec.ProfileID] += rec.HandshakeRTT
			profileLatencyCount[rec.ProfileID]++
		} else {
			failures++
			profileFailures[rec.ProfileID]++
		}
	}

	// JA3 Uniqueness Index: U_F = 1 - max_count(hash) / N
	metrics.JA3UniquenessIndex = computeUniquenessIndex(ja3Counts, n)
	metrics.JA4UniquenessIndex = computeUniquenessIndex(ja4Counts, n)

	// Fingerprint entropy (over JA3 hashes).
	metrics.FingerprintEntropy = normalizedEntropy(ja3Counts, n)

	// Profile entropy.
	metrics.ProfileEntropy = normalizedEntropy(profileCounts, n)

	// Fingerprint variance score: estimated from fingerprint diversity.
	// More diverse fingerprints → higher variance.
	// C = min(1.0, (unique_hashes / n) * 2)
	uniqueHashes := len(ja3Counts)
	metrics.VarianceScore = math.Min(1.0, float64(uniqueHashes)/float64(n)*2.0)

	// Latency metrics.
	metrics.FailureRate = float64(failures) / float64(n)
	if len(latencies) > 0 {
		metrics.MeanLatency = totalLatency / time.Duration(len(latencies))
		metrics.MedianLatency = medianDuration(latencies)
	}

	// Per-profile metrics.
	for profile, count := range profileCounts {
		metrics.ProfileReuseCounts[profile] = count
		totalForProfile := count
		failedForProfile := profileFailures[profile]
		metrics.ProfileFailureRates[profile] = float64(failedForProfile) / float64(totalForProfile)
		if profileLatencyCount[profile] > 0 {
			metrics.ProfileMeanLatencies[profile] = profileLatencySum[profile] / time.Duration(profileLatencyCount[profile])
		}
	}

	return metrics
}

// ComputeFitness computes a fitness score for a specific profile based on
// the adaptive algorithm: S(p) = w1*C + w2*U_F + w3*H'(X) - w4*reuse_p
func (s *StateEngine) ComputeFitness(profileID string, weights [4]float64) float64 {
	metrics := s.GetMetrics()
	return ComputeFitnessFromMetrics(profileID, metrics, weights)
}

// ComputeFitnessFromMetrics computes fitness from pre-computed metrics.
// S(p) = w1*C + w2*U_F + w3*H'(X) - w4*normalized_reuse_p
func ComputeFitnessFromMetrics(profileID string, metrics Metrics, weights [4]float64) float64 {
	reuseCount := metrics.ProfileReuseCounts[profileID]

	// Normalize reuse to [0, 1] range.
	var normalizedReuse float64
	if metrics.WindowSize > 0 {
		normalizedReuse = float64(reuseCount) / float64(metrics.WindowSize)
	}

	fitness := weights[0]*metrics.VarianceScore +
		weights[1]*metrics.JA3UniquenessIndex +
		weights[2]*metrics.ProfileEntropy -
		weights[3]*normalizedReuse

	return fitness
}

// activeRecords returns the current valid records in the sliding window.
func (s *StateEngine) activeRecords() []ConnectionRecord {
	records := make([]ConnectionRecord, s.count)
	for i := 0; i < s.count; i++ {
		idx := (s.head - s.count + i + s.windowSize) % s.windowSize
		records[i] = s.records[idx]
	}
	return records
}

// computeUniquenessIndex computes U_F = 1 - max_count(hash) / N.
func computeUniquenessIndex(counts map[string]int, n int) float64 {
	if n == 0 {
		return 1.0
	}
	maxCount := 0
	for _, c := range counts {
		if c > maxCount {
			maxCount = c
		}
	}
	return 1.0 - float64(maxCount)/float64(n)
}

// normalizedEntropy computes H'(X) = H(X) / log2(|X|).
// H(X) = -sum(p_i * log2(p_i)) for each category.
func normalizedEntropy(counts map[string]int, n int) float64 {
	if n == 0 || len(counts) <= 1 {
		return 0.0
	}

	var entropy float64
	for _, count := range counts {
		if count > 0 {
			p := float64(count) / float64(n)
			entropy -= p * math.Log2(p)
		}
	}

	// Normalize by maximum possible entropy.
	maxEntropy := math.Log2(float64(len(counts)))
	if maxEntropy == 0 {
		return 0.0
	}

	return entropy / maxEntropy
}

// medianDuration computes the median of a slice of durations.
func medianDuration(durations []time.Duration) time.Duration {
	if len(durations) == 0 {
		return 0
	}

	// Make a copy so we don't modify the original.
	sorted := make([]time.Duration, len(durations))
	copy(sorted, durations)

	// Sort durations.
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j] < sorted[i] {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	mid := len(sorted) / 2
	if len(sorted)%2 == 0 {
		return (sorted[mid-1] + sorted[mid]) / 2
	}
	return sorted[mid]
}
