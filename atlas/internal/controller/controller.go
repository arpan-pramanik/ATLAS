// Package controller implements the Adaptive Controller for ATLAS.
// It is the policy engine that ties together the Genome, Mutation Engine,
// Morphological State Engine, and TLS Profiles to make intelligent decisions
// about which fingerprint to use for each connection.
package controller

import (
	"fmt"
	"math"
	"math/rand"
	"sync"
	"time"

	"atlas/atlas/internal/config"
	"atlas/atlas/internal/engine"
	"atlas/atlas/internal/fingerprint"
	"atlas/atlas/internal/genome"
	"atlas/atlas/internal/morphological"

	utls "github.com/refraction-networking/utls"
	"github.com/sirupsen/logrus"
)

// AdaptiveController is the main policy engine that determines which
// TLS fingerprint to use for each outgoing connection.
type AdaptiveController struct {
	mu       sync.Mutex
	genome   *genome.TLSGenome
	engine   *engine.Engine
	state    *morphological.StateEngine
	profiles map[string]*utls.ClientHelloSpec
	rng      *rand.Rand
	log      *logrus.Entry

	// Controller configuration.
	weights          [4]float64 // Fitness weights: [confusion, uniqueness, entropy, reuse_penalty].
	softmaxAlpha     float64    // Temperature for softmax profile selection.
	entropyTargetMin float64    // Minimum entropy target (below this → more aggressive mutation).
	entropyTargetMax float64    // Maximum entropy target (above this → reduce mutation).
	reuseThreshold   int        // Maximum reuse count before forced rotation.
	latencyBudgetMs  int        // Maximum acceptable handshake latency in ms.
	failureThreshold float64    // Maximum acceptable failure rate per profile.
}

// NewAdaptiveController creates a new controller with all components wired together.
func NewAdaptiveController(
	genomeSeed []byte,
	engineConfig engine.MutationConfig,
	controllerCfg config.ControllerConfig,
	profileNames []string,
) (*AdaptiveController, error) {
	log := logrus.WithField("component", "controller")

	// Load available profiles.
	profiles := make(map[string]*utls.ClientHelloSpec)
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	if len(profileNames) == 0 {
		profileNames = config.AllProfileNames()
	}

	for _, name := range profileNames {
		spec, err := config.GetProfileByName(name, rng)
		if err != nil {
			log.Warnf("Skipping unknown profile %q: %v", name, err)
			continue
		}
		profiles[name] = spec
	}

	if len(profiles) == 0 {
		return nil, fmt.Errorf("no valid profiles loaded")
	}

	// Pick a random initial profile for the genome base.
	var baseSpec *utls.ClientHelloSpec
	var baseName string
	for name, spec := range profiles {
		baseSpec = spec
		baseName = name
		break
	}
	log.Infof("Initial profile: %s (generation 0)", baseName)

	// Create the TLS genome with evolutionary lineage.
	tlsGenome := genome.NewTLSGenome(genomeSeed, baseSpec)

	// Create the mutation engine.
	mutEngine := engine.NewEngine(engineConfig)

	// Create the state engine with configured window size.
	windowSize := controllerCfg.WindowSize
	if windowSize <= 0 {
		windowSize = 100
	}
	stateEngine := morphological.NewStateEngine(windowSize)

	// Parse weights.
	weights := controllerCfg.Weights
	if weights == [4]float64{} {
		weights = [4]float64{0.3, 0.3, 0.2, 0.2} // Default weights.
	}

	softmaxAlpha := controllerCfg.SoftmaxAlpha
	if softmaxAlpha == 0 {
		softmaxAlpha = 2.0
	}

	entropyMin := controllerCfg.EntropyTargetBand[0]
	entropyMax := controllerCfg.EntropyTargetBand[1]
	if entropyMin == 0 && entropyMax == 0 {
		entropyMin = 0.4
		entropyMax = 0.8
	}

	reuseThreshold := controllerCfg.ReuseThreshold
	if reuseThreshold <= 0 {
		reuseThreshold = 50
	}

	latencyBudget := controllerCfg.LatencyBudgetMs
	if latencyBudget <= 0 {
		latencyBudget = 5000 // 5 seconds default.
	}

	failureThreshold := controllerCfg.FailureRateThreshold
	if failureThreshold <= 0 {
		failureThreshold = 0.1
	}

	return &AdaptiveController{
		genome:           tlsGenome,
		engine:           mutEngine,
		state:            stateEngine,
		profiles:         profiles,
		rng:              rng,
		log:              log,
		weights:          weights,
		softmaxAlpha:     softmaxAlpha,
		entropyTargetMin: entropyMin,
		entropyTargetMax: entropyMax,
		reuseThreshold:   reuseThreshold,
		latencyBudgetMs:  latencyBudget,
		failureThreshold: failureThreshold,
	}, nil
}

// NextSpec determines the next ClientHelloSpec to use for an outgoing connection.
// It returns the mutated spec, the selected profile name, and an optional
// timing jitter delay that should be applied before the handshake.
func (c *AdaptiveController) NextSpec(targetHost string) (*utls.ClientHelloSpec, string, time.Duration, *fingerprint.FingerprintResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Step 1: Get current metrics from the state engine.
	metrics := c.state.GetMetrics()

	// Step 2: Determine mutation intensity based on entropy state.
	intensity := c.determineIntensity(metrics)

	// Step 3: Select a profile using fitness-weighted softmax sampling.
	selectedProfile, selectedName := c.selectProfile(metrics)

	// Step 4: Apply the selected profile as the new genome base.
	c.genome.SetCurrent(selectedProfile)

	// Step 5: Mutate the spec using the engine (evolutionary lineage).
	mutatedSpec := c.engine.Mutate(c.genome.CurrentSpec(), c.genome.Rng(), intensity)

	// Step 6: Set SNI for the target host on any SNI extension.
	setSNI(mutatedSpec, targetHost)

	// Step 7: Compute the fingerprint of the mutated spec.
	fp := fingerprint.Extract(mutatedSpec)

	// Step 8: Evolve the genome (record lineage).
	c.genome.Evolve(fp.JA3Hash)
	c.genome.SetCurrent(mutatedSpec)

	// Step 9: Determine timing jitter.
	jitter := c.computeJitter(intensity)

	c.log.WithFields(logrus.Fields{
		"profile":    selectedName,
		"generation": c.genome.Generation(),
		"ja3":        fp.JA3Hash[:12],
		"intensity":  intensity,
		"jitter_ms":  jitter.Milliseconds(),
	}).Debug("Generated next ClientHello spec")

	return mutatedSpec, selectedName, jitter, fp, nil
}

// RecordResult reports the outcome of a connection back to the state engine.
func (c *AdaptiveController) RecordResult(profileID, ja3Hash, ja4Hash string, rtt time.Duration, success bool) {
	c.state.RecordConnection(morphological.ConnectionRecord{
		Timestamp:       time.Now(),
		ProfileID:       profileID,
		FingerprintHash: ja3Hash,
		JA4Hash:         ja4Hash,
		HandshakeRTT:    rtt,
		Success:         success,
		Generation:      c.genome.Generation(),
	})
}

// GetMetrics returns the current metrics from the state engine.
func (c *AdaptiveController) GetMetrics() morphological.Metrics {
	return c.state.GetMetrics()
}

// GetGeneration returns the current genome generation.
func (c *AdaptiveController) GetGeneration() int {
	return c.genome.Generation()
}

// GetLineage returns the fingerprint lineage history.
func (c *AdaptiveController) GetLineage() []string {
	return c.genome.GetLineage()
}

// determineIntensity decides mutation intensity based on current entropy state.
func (c *AdaptiveController) determineIntensity(metrics morphological.Metrics) engine.MutationIntensity {
	entropy := metrics.ProfileEntropy

	// If entropy is below minimum target → need more diversity.
	if entropy < c.entropyTargetMin {
		c.log.Debug("Entropy below target band → high intensity")
		return engine.IntensityHigh
	}

	// If entropy is above maximum target → too much randomness, blend in.
	if entropy > c.entropyTargetMax {
		c.log.Debug("Entropy above target band → low intensity")
		return engine.IntensityLow
	}

	return engine.IntensityMedium
}

// selectProfile uses fitness-weighted softmax sampling to choose a profile.
func (c *AdaptiveController) selectProfile(metrics morphological.Metrics) (*utls.ClientHelloSpec, string) {
	type scored struct {
		name    string
		spec    *utls.ClientHelloSpec
		fitness float64
	}

	var candidates []scored

	for name, spec := range c.profiles {
		// Filter: skip profiles with excessive failure rates.
		if rate, ok := metrics.ProfileFailureRates[name]; ok && rate > c.failureThreshold {
			c.log.Debugf("Skipping profile %q due to high failure rate (%.2f)", name, rate)
			continue
		}

		// Filter: skip profiles with excessive latency.
		if latency, ok := metrics.ProfileMeanLatencies[name]; ok {
			if latency.Milliseconds() > int64(c.latencyBudgetMs) {
				c.log.Debugf("Skipping profile %q due to high latency (%v)", name, latency)
				continue
			}
		}

		// Filter: force rotation if reuse exceeds threshold.
		if count, ok := metrics.ProfileReuseCounts[name]; ok && count > c.reuseThreshold {
			c.log.Debugf("Profile %q exceeded reuse threshold (%d > %d), deprioritizing", name, count, c.reuseThreshold)
			// Don't skip entirely, just score lower (the reuse penalty in fitness handles this).
		}

		fitness := morphological.ComputeFitnessFromMetrics(name, metrics, c.weights)
		candidates = append(candidates, scored{name, spec, fitness})
	}

	// Fallback: if all profiles filtered out, use all of them.
	if len(candidates) == 0 {
		c.log.Warn("All profiles filtered out, using all profiles")
		for name, spec := range c.profiles {
			fitness := morphological.ComputeFitnessFromMetrics(name, metrics, c.weights)
			candidates = append(candidates, scored{name, spec, fitness})
		}
	}

	// Single candidate → use it.
	if len(candidates) == 1 {
		return candidates[0].spec, candidates[0].name
	}

	// Softmax sampling: P(p) ∝ exp(α * S(p)).
	maxFitness := candidates[0].fitness
	for _, c := range candidates {
		if c.fitness > maxFitness {
			maxFitness = c.fitness
		}
	}

	weights := make([]float64, len(candidates))
	var totalWeight float64
	for i, cand := range candidates {
		// Subtract max for numerical stability.
		weights[i] = math.Exp(c.softmaxAlpha * (cand.fitness - maxFitness))
		totalWeight += weights[i]
	}

	// Sample from the distribution.
	r := c.rng.Float64() * totalWeight
	cumulative := 0.0
	for i, w := range weights {
		cumulative += w
		if r <= cumulative {
			return candidates[i].spec, candidates[i].name
		}
	}

	// Fallback (shouldn't happen).
	last := len(candidates) - 1
	return candidates[last].spec, candidates[last].name
}

// computeJitter returns a random delay to apply before the handshake
// to disrupt timing-based fingerprinting.
func (c *AdaptiveController) computeJitter(intensity engine.MutationIntensity) time.Duration {
	var maxJitterMs int
	switch intensity {
	case engine.IntensityLow:
		maxJitterMs = 10
	case engine.IntensityMedium:
		maxJitterMs = 50
	case engine.IntensityHigh:
		maxJitterMs = 150
	default:
		maxJitterMs = 30
	}

	if maxJitterMs <= 0 {
		return 0
	}

	jitterMs := c.rng.Intn(maxJitterMs)
	return time.Duration(jitterMs) * time.Millisecond
}

// setSNI finds the SNI extension and sets the server name.
func setSNI(spec *utls.ClientHelloSpec, hostname string) {
	for _, ext := range spec.Extensions {
		if sni, ok := ext.(*utls.SNIExtension); ok {
			sni.ServerName = hostname
			return
		}
	}
	// No SNI extension found; add one at the beginning.
	spec.Extensions = append([]utls.TLSExtension{&utls.SNIExtension{ServerName: hostname}}, spec.Extensions...)
}
