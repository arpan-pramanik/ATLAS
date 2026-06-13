// Package config provides configuration types and loading for the ATLAS system.
//
// Configuration is stored in JSON format and all fields have sensible defaults.
// If no config file is provided, DefaultConfig() returns a production-ready
// configuration. The config file is optional - any fields not present in the
// JSON will retain their default values.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// Config is the top-level ATLAS configuration.
type Config struct {
	// Proxy holds the listener and TLS certificate settings.
	Proxy ProxyConfig `json:"proxy"`

	// Mutation holds probabilities for each fingerprint mutation type.
	// All probabilities are in the range [0.0, 1.0].
	Mutation MutationConfig `json:"mutation"`

	// Controller holds parameters for the adaptive controller.
	Controller ControllerConfig `json:"controller"`

	// Seed configures the entropy source for randomness.
	Seed SeedConfig `json:"seed"`

	// Profiles lists the names of predefined TLS profiles to use.
	// Valid names: "chrome", "firefox", "safari", "randomized".
	Profiles []string `json:"profiles"`

	// LogLevel controls logging verbosity.
	// Valid values: "debug", "info", "warn", "error".
	LogLevel string `json:"log_level"`
}

// ProxyConfig holds settings for the MITM proxy listener.
type ProxyConfig struct {
	// Listen is the address to listen on (e.g. ":1080").
	Listen string `json:"listen"`

	// CertFile is the path to the PEM-encoded MITM CA certificate.
	CertFile string `json:"cert_file"`

	// KeyFile is the path to the PEM-encoded MITM CA private key.
	KeyFile string `json:"key_file"`
}

// MutationConfig holds probabilities for each mutation type applied to TLS
// ClientHello fingerprints. Each value must be in [0.0, 1.0].
type MutationConfig struct {
	// ExtensionShuffle is the probability of shuffling extension order.
	ExtensionShuffle float64 `json:"extension_shuffle"`

	// CipherShuffle is the probability of shuffling cipher suite order.
	CipherShuffle float64 `json:"cipher_shuffle"`

	// SupportedGroupsShuffle is the probability of shuffling supported groups.
	SupportedGroupsShuffle float64 `json:"supported_groups_shuffle"`

	// ALPNShuffle is the probability of shuffling the ALPN protocol list.
	ALPNShuffle float64 `json:"alpn_shuffle"`

	// GREASEMutation is the probability of adding/modifying GREASE values.
	GREASEMutation float64 `json:"grease_mutation"`

	// PaddingMutation is the probability of modifying the padding extension.
	PaddingMutation float64 `json:"padding_mutation"`

	// CipherSubset is the probability of presenting a random subset of cipher suites
	// instead of the full set from the profile.
	CipherSubset float64 `json:"cipher_subset"`
}

// ControllerConfig holds parameters for the adaptive feedback controller
// that tunes mutation aggressiveness based on observed outcomes.
type ControllerConfig struct {
	// WindowSize is the number of recent connections to consider for
	// computing fitness metrics.
	WindowSize int `json:"window_size"`

	// Weights holds the four objective weights [w1, w2, w3, w4]:
	//   w1 - fingerprint entropy (diversity)
	//   w2 - connection success rate
	//   w3 - latency penalty
	//   w4 - detector evasion score
	Weights [4]float64 `json:"weights"`

	// SoftmaxAlpha is the temperature parameter for softmax profile selection.
	// Higher values make selection more deterministic.
	SoftmaxAlpha float64 `json:"softmax_alpha"`

	// EntropyTargetBand defines the [min, max] target range for fingerprint
	// entropy. The controller adjusts mutation rates to keep entropy within
	// this band.
	EntropyTargetBand [2]float64 `json:"entropy_target_band"`

	// ReuseThreshold is the maximum number of times a fingerprint can be
	// reused before the controller forces a new mutation.
	ReuseThreshold int `json:"reuse_threshold"`

	// LatencyBudgetMs is the maximum acceptable additional latency (in
	// milliseconds) introduced by fingerprint mutation.
	LatencyBudgetMs int `json:"latency_budget_ms"`

	// FailureRateThreshold is the connection failure rate [0.0, 1.0] above
	// which the controller will reduce mutation aggressiveness.
	FailureRateThreshold float64 `json:"failure_rate_threshold"`
}

// SeedConfig configures the entropy source for the random number generator.
type SeedConfig struct {
	// Source is the entropy source to use.
	// Valid values: "crypto" (crypto/rand), "system" (time-based), "qrng" (quantum RNG API).
	Source string `json:"source"`
}

// DefaultConfig returns a Config with sensible production defaults.
func DefaultConfig() *Config {
	return &Config{
		Proxy: ProxyConfig{
			Listen:   ":1080",
			CertFile: "mitm-cert.pem",
			KeyFile:  "mitm-key.pem",
		},
		Mutation: MutationConfig{
			ExtensionShuffle:       0.3,
			CipherShuffle:         0.2,
			SupportedGroupsShuffle: 0.15,
			ALPNShuffle:           0.1,
			GREASEMutation:        0.25,
			PaddingMutation:       0.2,
			CipherSubset:          0.1,
		},
		Controller: ControllerConfig{
			WindowSize:           100,
			Weights:              [4]float64{0.3, 0.3, 0.2, 0.2},
			SoftmaxAlpha:         1.0,
			EntropyTargetBand:    [2]float64{2.0, 4.0},
			ReuseThreshold:       5,
			LatencyBudgetMs:      50,
			FailureRateThreshold: 0.05,
		},
		Seed: SeedConfig{
			Source: "cloudflare",
		},
		Profiles: []string{"chrome", "firefox", "safari"},
		LogLevel: "info",
	}
}

// LoadConfig reads a JSON configuration file from path and returns the
// resulting Config. The file is optional: fields not present in the JSON
// retain their default values from DefaultConfig().
//
// If path is empty, DefaultConfig() is returned directly.
func LoadConfig(path string) (*Config, error) {
	cfg := DefaultConfig()

	if path == "" {
		return cfg, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: failed to read %s: %w", path, err)
	}

	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("config: failed to parse %s: %w", path, err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config: validation failed: %w", err)
	}

	return cfg, nil
}

// Validate checks that all configuration values are within acceptable ranges.
func (c *Config) Validate() error {
	var errs []string

	// Validate proxy config.
	if c.Proxy.Listen == "" {
		errs = append(errs, "proxy.listen must not be empty")
	}

	// Validate mutation probabilities.
	for _, p := range []struct {
		name string
		val  float64
	}{
		{"mutation.extension_shuffle", c.Mutation.ExtensionShuffle},
		{"mutation.cipher_shuffle", c.Mutation.CipherShuffle},
		{"mutation.supported_groups_shuffle", c.Mutation.SupportedGroupsShuffle},
		{"mutation.alpn_shuffle", c.Mutation.ALPNShuffle},
		{"mutation.grease_mutation", c.Mutation.GREASEMutation},
		{"mutation.padding_mutation", c.Mutation.PaddingMutation},
		{"mutation.cipher_subset", c.Mutation.CipherSubset},
	} {
		if p.val < 0.0 || p.val > 1.0 {
			errs = append(errs, fmt.Sprintf("%s must be in [0.0, 1.0], got %f", p.name, p.val))
		}
	}

	// Validate controller config.
	if c.Controller.WindowSize <= 0 {
		errs = append(errs, "controller.window_size must be > 0")
	}
	if c.Controller.SoftmaxAlpha <= 0 {
		errs = append(errs, "controller.softmax_alpha must be > 0")
	}
	if c.Controller.EntropyTargetBand[0] >= c.Controller.EntropyTargetBand[1] {
		errs = append(errs, "controller.entropy_target_band[0] must be < entropy_target_band[1]")
	}
	if c.Controller.ReuseThreshold <= 0 {
		errs = append(errs, "controller.reuse_threshold must be > 0")
	}
	if c.Controller.LatencyBudgetMs <= 0 {
		errs = append(errs, "controller.latency_budget_ms must be > 0")
	}
	if c.Controller.FailureRateThreshold < 0.0 || c.Controller.FailureRateThreshold > 1.0 {
		errs = append(errs, fmt.Sprintf("controller.failure_rate_threshold must be in [0.0, 1.0], got %f", c.Controller.FailureRateThreshold))
	}
	for i, w := range c.Controller.Weights {
		if w < 0.0 {
			errs = append(errs, fmt.Sprintf("controller.weights[%d] must be >= 0, got %f", i, w))
		}
	}

	// Validate seed source.
	switch c.Seed.Source {
	case "crypto", "system", "cloudflare", "qrng":
		// ok
	default:
		errs = append(errs, fmt.Sprintf("seed.source must be one of [crypto, system, qrng], got %q", c.Seed.Source))
	}

	// Validate profiles.
	validProfiles := map[string]bool{
		"chrome": true, "firefox": true, "safari": true, "randomized": true,
	}
	for _, p := range c.Profiles {
		if !validProfiles[p] {
			errs = append(errs, fmt.Sprintf("profiles: unknown profile %q", p))
		}
	}
	if len(c.Profiles) == 0 {
		errs = append(errs, "profiles must contain at least one profile")
	}

	// Validate log level.
	switch strings.ToLower(c.LogLevel) {
	case "debug", "info", "warn", "error":
		// ok
	default:
		errs = append(errs, fmt.Sprintf("log_level must be one of [debug, info, warn, error], got %q", c.LogLevel))
	}

	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}
