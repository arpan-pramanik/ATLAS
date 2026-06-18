package benchmark

import (
	"fmt"
	"math"
	"time"

	"atlas/atlas/internal/config"
	"atlas/atlas/internal/controller"
	"atlas/atlas/internal/engine"
	"atlas/atlas/internal/genome"

	"github.com/sirupsen/logrus"
)

// BenchmarkResults holds the results of an evaluation run.
type BenchmarkResults struct {
	TotalConnections int
	UniqueJA3        int
	UniqueJA4        int
	JA3Entropy       float64
	ProfileEntropy   float64
	AverageRTT       time.Duration
	VarianceScore    float64
	Generations      int
}

// RunBenchmark executes a simulated workload through the AdaptiveController
// to evaluate fingerprint diversity, entropy, and performance.
func RunBenchmark(iterations int, simulateLatency time.Duration, cfg *config.Config) (*BenchmarkResults, error) {
	// Silence verbose logging for the benchmark run.
	logrus.SetLevel(logrus.ErrorLevel)

	// Generate seed.
	seedSource := genome.SeedCryptoRand
	if cfg.Seed.Source == "system" {
		seedSource = genome.SeedSystem
	} else if cfg.Seed.Source == "cloudflare" {
		seedSource = genome.SeedCloudflare
	}
	seed, err := genome.GenerateSeed(seedSource)
	if err != nil {
		return nil, fmt.Errorf("failed to generate seed: %v", err)
	}

	engineCfg := engine.MutationConfig{
		ExtensionShuffleProbability:       cfg.Mutation.ExtensionShuffle,
		CipherShuffleProbability:          cfg.Mutation.CipherShuffle,
		CipherSubsetProbability:           cfg.Mutation.CipherSubset,
		SupportedGroupsShuffleProbability: cfg.Mutation.SupportedGroupsShuffle,
		ALPNShuffleProbability:            cfg.Mutation.ALPNShuffle,
		GREASEMutationProbability:         cfg.Mutation.GREASEMutation,
		PaddingMutationProbability:        cfg.Mutation.PaddingMutation,
	}

	ctrl, err := controller.NewAdaptiveController(
		seed,
		engineCfg,
		cfg.Controller,
		cfg.Profiles,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to init controller: %v", err)
	}

	// Track seen fingerprints globally.
	seenJA3 := make(map[string]int)
	seenJA4 := make(map[string]int)
	profileCounts := make(map[string]int)

	var totalVariance float64
	var totalRTT time.Duration

	// Execute simulated connections.
	for i := 0; i < iterations; i++ {
		start := time.Now()
		_, profile, _, fp, err := ctrl.NextSpec("example.com")
		if err != nil {
			return nil, fmt.Errorf("NextSpec failed at iteration %d: %v", i, err)
		}

		// Simulate handshake latency + some jitter
		time.Sleep(simulateLatency)
		rtt := time.Since(start)

		seenJA3[fp.JA3Hash]++
		seenJA4[fp.JA4Hash]++
		profileCounts[profile]++
		totalRTT += rtt

		// Report success back to the controller.
		ctrl.RecordResult(profile, fp.JA3Hash, fp.JA4Hash, rtt, true)

		metrics := ctrl.GetMetrics()
		totalVariance += metrics.VarianceScore
	}

	// Calculate global entropy metrics over the entire run.
	ja3Entropy := normalizedEntropy(seenJA3, iterations)
	profEntropy := normalizedEntropy(profileCounts, iterations)

	results := &BenchmarkResults{
		TotalConnections: iterations,
		UniqueJA3:        len(seenJA3),
		UniqueJA4:        len(seenJA4),
		JA3Entropy:       ja3Entropy,
		ProfileEntropy:   profEntropy,
		AverageRTT:       totalRTT / time.Duration(iterations),
		VarianceScore:    totalVariance / float64(iterations),
		Generations:      ctrl.GetGeneration(),
	}

	return results, nil
}

// PrintResults formats the benchmark results as a textual report.
func PrintResults(res *BenchmarkResults) string {
	report := "ATLAS Benchmark Evaluation Report\n"
	report += "=================================\n"
	report += fmt.Sprintf("Total Connections Simulated: %d\n", res.TotalConnections)
	report += fmt.Sprintf("Total Generations Evolved:   %d\n", res.Generations)
	report += "\n-- Fingerprint Diversity --\n"
	report += fmt.Sprintf("Unique JA3 Hashes:           %d\n", res.UniqueJA3)
	report += fmt.Sprintf("Unique JA4 Hashes:           %d\n", res.UniqueJA4)
	report += fmt.Sprintf("Global JA3 Entropy (H'):     %.4f\n", res.JA3Entropy)
	report += fmt.Sprintf("Profile Spread Entropy:      %.4f\n", res.ProfileEntropy)
	report += fmt.Sprintf("Fingerprint Variance Score:  %.4f\n", res.VarianceScore)
	report += "\n-- Performance --\n"
	report += fmt.Sprintf("Average Handshake RTT:       %v\n", res.AverageRTT)
	return report
}

// normalizedEntropy computes H'(X) = H(X) / log2(|X|)
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

	maxEntropy := math.Log2(float64(len(counts)))
	if maxEntropy == 0 {
		return 0.0
	}

	return entropy / maxEntropy
}
