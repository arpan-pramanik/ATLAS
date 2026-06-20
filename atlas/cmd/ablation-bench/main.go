package main

import (
	"fmt"
	"time"
	"os"

	"atlas/atlas/internal/benchmark"
	"atlas/atlas/internal/config"
)

func runCondition(name string, iterations int, latencyMs int, cfg *config.Config) string {
	fmt.Printf("Running condition: %s\n", name)
	start := time.Now()
	res, err := benchmark.RunBenchmark(iterations, time.Duration(latencyMs)*time.Millisecond, cfg)
	if err != nil {
		return fmt.Sprintf("Error in %s: %v\n", name, err)
	}
	elapsed := time.Since(start)
	
	out := fmt.Sprintf("=== Condition: %s ===\n", name)
	out += benchmark.PrintResults(res)
	out += fmt.Sprintf("\nTime elapsed: %v\n\n", elapsed)
	return out
}

func main() {
	iterations := 500
	latencyMs := 20
	var finalReport string

	fmt.Println("Starting ATLAS Ablation Study Benchmark...")

	// 1. Baseline (Static Mimic)
	cfgBaseline := config.DefaultConfig()
	cfgBaseline.Profiles = []string{"chrome"}
	cfgBaseline.Mutation = config.MutationConfig{} // All zeros
	cfgBaseline.Controller.Weights = [4]float64{0, 0, 0, 0}
	finalReport += runCondition("1. Baseline (Static Mimic)", iterations, latencyMs, cfgBaseline)

	// 2. Multi-Profile (Random rotation, no mutation)
	cfgMulti := config.DefaultConfig()
	cfgMulti.Profiles = []string{"chrome", "firefox", "safari"}
	cfgMulti.Mutation = config.MutationConfig{}
	cfgMulti.Controller.Weights = [4]float64{0, 0, 0, 0}
	finalReport += runCondition("2. Multi-Profile (No Mutation)", iterations, latencyMs, cfgMulti)

	// 3. Static Random (Random mutations, no adaptive feedback)
	cfgRandom := config.DefaultConfig()
	cfgRandom.Profiles = []string{"chrome"}
	cfgRandom.Mutation = config.MutationConfig{
		ExtensionShuffle:       0.8,
		CipherShuffle:          0.8,
		SupportedGroupsShuffle: 0.8,
		ALPNShuffle:            0.8,
		GREASEMutation:         0.8,
		PaddingMutation:        0.8,
		CipherSubset:           0.8,
	}
	cfgRandom.Controller.Weights = [4]float64{0, 0, 0, 0}
	finalReport += runCondition("3. Static-Random", iterations, latencyMs, cfgRandom)

	// 4. Full-Adaptive (ATLAS Default)
	cfgAdaptive := config.DefaultConfig()
	finalReport += runCondition("4. Full-Adaptive (ATLAS)", iterations, latencyMs, cfgAdaptive)

	err := os.WriteFile("ablation_results.txt", []byte(finalReport), 0644)
	if err != nil {
		fmt.Printf("Failed to write results: %v\n", err)
	} else {
		fmt.Println("Successfully wrote ablation_results.txt")
	}
}
