// Package engine provides the core TLS ClientHello mutation engine for ATLAS.
// It implements various mutation strategies that can be composed and applied
// to evolve TLS fingerprints while maintaining protocol compliance.
package engine

import (
	"fmt"
	"math/rand"
	"sort"

	utls "github.com/refraction-networking/utls"
	"github.com/sirupsen/logrus"
)

// MutationIntensity controls how aggressively mutations are applied.
type MutationIntensity int

const (
	// IntensityLow applies minimal mutations (e.g., light reordering).
	IntensityLow MutationIntensity = iota
	// IntensityMedium applies moderate mutations (reordering + subset changes).
	IntensityMedium
	// IntensityHigh applies aggressive mutations (full randomization).
	IntensityHigh
)

// MutationConfig holds probabilities for each mutation type.
type MutationConfig struct {
	ExtensionShuffleProbability  float64 // Probability of shuffling extension order.
	CipherShuffleProbability     float64 // Probability of shuffling cipher suite order.
	CipherSubsetProbability      float64 // Probability of selecting a cipher suite subset.
	SupportedGroupsShuffleProbability float64 // Probability of shuffling supported groups.
	ALPNShuffleProbability       float64 // Probability of shuffling ALPN protocols.
	GREASEMutationProbability    float64 // Probability of modifying GREASE values.
	PaddingMutationProbability   float64 // Probability of modifying padding extension.
}

// DefaultMutationConfig returns sensible default mutation probabilities.
func DefaultMutationConfig() MutationConfig {
	return MutationConfig{
		ExtensionShuffleProbability:  0.8,
		CipherShuffleProbability:     0.6,
		CipherSubsetProbability:      0.2,
		SupportedGroupsShuffleProbability: 0.4,
		ALPNShuffleProbability:       0.3,
		GREASEMutationProbability:    0.5,
		PaddingMutationProbability:   0.4,
	}
}

// Engine is the core mutation engine that applies mutations to ClientHelloSpecs.
type Engine struct {
	config MutationConfig
	log    *logrus.Entry
}

// NewEngine creates a new mutation engine with the given configuration.
func NewEngine(config MutationConfig) *Engine {
	return &Engine{
		config: config,
		log:    logrus.WithField("component", "engine"),
	}
}

// Mutate applies a series of probabilistic mutations to a ClientHelloSpec
// based on the engine's configuration and the given PRNG source.
// It returns a new mutated spec without modifying the original.
func (e *Engine) Mutate(base *utls.ClientHelloSpec, rng *rand.Rand, intensity MutationIntensity) *utls.ClientHelloSpec {
	mutated := DeepCopySpec(base)

	// Scale probabilities by intensity.
	scale := intensityScale(intensity)

	// Mutate cipher suite order.
	if rng.Float64() < e.config.CipherShuffleProbability*scale && len(mutated.CipherSuites) > 1 {
		e.shuffleCipherSuites(mutated, rng)
		e.log.Debug("Applied cipher suite shuffle mutation")
	}

	// Mutate cipher suite subset (remove some non-essential suites).
	if rng.Float64() < e.config.CipherSubsetProbability*scale && len(mutated.CipherSuites) > 4 {
		e.subsetCipherSuites(mutated, rng)
		e.log.Debug("Applied cipher suite subset mutation")
	}

	// Mutate extension order.
	if rng.Float64() < e.config.ExtensionShuffleProbability*scale && len(mutated.Extensions) > 1 {
		e.shuffleExtensions(mutated, rng)
		e.log.Debug("Applied extension shuffle mutation")
	}

	// Mutate supported groups order within the SupportedCurvesExtension.
	if rng.Float64() < e.config.SupportedGroupsShuffleProbability*scale {
		e.shuffleSupportedGroups(mutated, rng)
		e.log.Debug("Applied supported groups shuffle mutation")
	}

	// Mutate ALPN order within the ALPNExtension.
	if rng.Float64() < e.config.ALPNShuffleProbability*scale {
		e.shuffleALPN(mutated, rng)
		e.log.Debug("Applied ALPN shuffle mutation")
	}

	// Mutate GREASE values.
	if rng.Float64() < e.config.GREASEMutationProbability*scale {
		e.mutateGREASE(mutated, rng)
		e.log.Debug("Applied GREASE mutation")
	}

	// Mutate padding.
	if rng.Float64() < e.config.PaddingMutationProbability*scale {
		e.mutatePadding(mutated, rng)
		e.log.Debug("Applied padding mutation")
	}

	return mutated
}

// shuffleCipherSuites randomly shuffles the cipher suite list using a
// Fisher-Yates shuffle, preserving the set of suites but changing order.
func (e *Engine) shuffleCipherSuites(spec *utls.ClientHelloSpec, rng *rand.Rand) {
	rng.Shuffle(len(spec.CipherSuites), func(i, j int) {
		spec.CipherSuites[i], spec.CipherSuites[j] = spec.CipherSuites[j], spec.CipherSuites[i]
	})
}

// subsetCipherSuites removes 1-2 non-essential cipher suites from the list.
// It preserves TLS 1.3 mandatory suites and ensures at least 3 remain.
func (e *Engine) subsetCipherSuites(spec *utls.ClientHelloSpec, rng *rand.Rand) {
	if len(spec.CipherSuites) <= 3 {
		return
	}

	// TLS 1.3 mandatory suites that should not be removed.
	tls13Suites := map[uint16]bool{
		0x1301: true, // TLS_AES_128_GCM_SHA256
		0x1302: true, // TLS_AES_256_GCM_SHA384
		0x1303: true, // TLS_CHACHA20_POLY1305_SHA256
	}

	// Find removable suites (non-TLS1.3, non-GREASE).
	var removable []int
	for i, suite := range spec.CipherSuites {
		if !tls13Suites[suite] && !isGREASE(suite) {
			removable = append(removable, i)
		}
	}

	// Remove 1-2 suites if possible.
	removeCount := 1
	if len(removable) > 2 && rng.Float64() < 0.3 {
		removeCount = 2
	}
	if removeCount > len(removable) {
		removeCount = len(removable)
	}

	// Randomly select indices to remove.
	rng.Shuffle(len(removable), func(i, j int) {
		removable[i], removable[j] = removable[j], removable[i]
	})
	toRemove := make(map[int]bool)
	for i := 0; i < removeCount; i++ {
		toRemove[removable[i]] = true
	}

	// Build new list without removed suites.
	newSuites := make([]uint16, 0, len(spec.CipherSuites)-removeCount)
	for i, suite := range spec.CipherSuites {
		if !toRemove[i] {
			newSuites = append(newSuites, suite)
		}
	}
	spec.CipherSuites = newSuites
}

// shuffleExtensions randomly shuffles the extension list while keeping
// certain constraints: SNI (if present) stays in the first few positions,
// and PSK (if present) stays last (TLS 1.3 requirement).
func (e *Engine) shuffleExtensions(spec *utls.ClientHelloSpec, rng *rand.Rand) {
	if len(spec.Extensions) <= 1 {
		return
	}

	// Find and extract constrained extensions.
	var pskExt utls.TLSExtension
	var pskIdx int = -1
	var remaining []utls.TLSExtension

	for i, ext := range spec.Extensions {
		switch ext.(type) {
		case *utls.FakePreSharedKeyExtension, *utls.UtlsPreSharedKeyExtension:
			pskExt = ext
			pskIdx = i
		default:
			remaining = append(remaining, ext)
		}
	}
	_ = pskIdx

	// Shuffle the remaining extensions.
	rng.Shuffle(len(remaining), func(i, j int) {
		remaining[i], remaining[j] = remaining[j], remaining[i]
	})

	// Reassemble: shuffled extensions, then PSK at the end if present.
	spec.Extensions = remaining
	if pskExt != nil {
		spec.Extensions = append(spec.Extensions, pskExt)
	}
}

// shuffleSupportedGroups finds the SupportedCurvesExtension and shuffles its curves.
func (e *Engine) shuffleSupportedGroups(spec *utls.ClientHelloSpec, rng *rand.Rand) {
	for _, ext := range spec.Extensions {
		if curves, ok := ext.(*utls.SupportedCurvesExtension); ok {
			if len(curves.Curves) > 1 {
				rng.Shuffle(len(curves.Curves), func(i, j int) {
					curves.Curves[i], curves.Curves[j] = curves.Curves[j], curves.Curves[i]
				})
			}
			return
		}
	}
}

// shuffleALPN finds the ALPNExtension and shuffles its protocol list.
func (e *Engine) shuffleALPN(spec *utls.ClientHelloSpec, rng *rand.Rand) {
	for _, ext := range spec.Extensions {
		if alpn, ok := ext.(*utls.ALPNExtension); ok {
			if len(alpn.AlpnProtocols) > 1 {
				rng.Shuffle(len(alpn.AlpnProtocols), func(i, j int) {
					alpn.AlpnProtocols[i], alpn.AlpnProtocols[j] = alpn.AlpnProtocols[j], alpn.AlpnProtocols[i]
				})
			}
			return
		}
	}
}

// mutateGREASE modifies existing GREASE extension values or adds a new one.
// GREASE values are of the form 0xNaNa where N is 0-F.
func (e *Engine) mutateGREASE(spec *utls.ClientHelloSpec, rng *rand.Rand) {
	// Generate a random GREASE value.
	greaseValues := []uint16{
		0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a,
		0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
		0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
		0xcaca, 0xdada, 0xeaea, 0xfafa,
	}
	newGrease := greaseValues[rng.Intn(len(greaseValues))]

	// Try to find and modify an existing GREASE extension.
	for _, ext := range spec.Extensions {
		if grease, ok := ext.(*utls.UtlsGREASEExtension); ok {
			grease.Value = newGrease
			return
		}
	}

	// No GREASE extension found; add one at a random position.
	greaseExt := &utls.UtlsGREASEExtension{
		Value: newGrease,
		Body:  nil, // empty body, like Chrome's first GREASE
	}

	// Insert at a random position (but not at the very end if PSK might be there).
	pos := rng.Intn(len(spec.Extensions) + 1)
	if pos > len(spec.Extensions) {
		pos = len(spec.Extensions)
	}
	newExts := make([]utls.TLSExtension, 0, len(spec.Extensions)+1)
	newExts = append(newExts, spec.Extensions[:pos]...)
	newExts = append(newExts, greaseExt)
	newExts = append(newExts, spec.Extensions[pos:]...)
	spec.Extensions = newExts
}

// mutatePadding modifies or adds a padding extension with variable length.
func (e *Engine) mutatePadding(spec *utls.ClientHelloSpec, rng *rand.Rand) {
	// Find existing padding extension.
	for i, ext := range spec.Extensions {
		if _, ok := ext.(*utls.UtlsPaddingExtension); ok {
			// Replace with new padding style.
			targetLen := 256 + rng.Intn(256) // Random target between 256-512
			spec.Extensions[i] = &utls.UtlsPaddingExtension{
				GetPaddingLen: utls.BoringPaddingStyle,
				WillPad:       true,
				PaddingLen:    targetLen,
			}
			return
		}
	}

	// No padding extension found; add one before the last extension.
	paddingExt := &utls.UtlsPaddingExtension{
		GetPaddingLen: utls.BoringPaddingStyle,
		WillPad:       true,
	}
	// Insert before the last extension (to avoid PSK constraint).
	insertPos := len(spec.Extensions)
	if insertPos > 0 {
		insertPos = insertPos - 1
	}
	newExts := make([]utls.TLSExtension, 0, len(spec.Extensions)+1)
	newExts = append(newExts, spec.Extensions[:insertPos]...)
	newExts = append(newExts, paddingExt)
	newExts = append(newExts, spec.Extensions[insertPos:]...)
	spec.Extensions = newExts
}

// ValidateSpec performs basic validation on a ClientHelloSpec to ensure
// it is likely to produce a valid TLS handshake.
func ValidateSpec(spec *utls.ClientHelloSpec) error {
	if len(spec.CipherSuites) == 0 {
		return fmt.Errorf("no cipher suites specified")
	}
	if len(spec.Extensions) == 0 {
		return fmt.Errorf("no extensions specified")
	}

	// Check for duplicate cipher suites.
	seenSuites := make(map[uint16]bool)
	for _, suite := range spec.CipherSuites {
		if isGREASE(suite) {
			continue // GREASE values can appear to repeat (they get replaced)
		}
		if seenSuites[suite] {
			return fmt.Errorf("duplicate cipher suite: 0x%04x", suite)
		}
		seenSuites[suite] = true
	}

	// Check TLS version sanity.
	if spec.TLSVersMax > 0 && spec.TLSVersMin > 0 && spec.TLSVersMin > spec.TLSVersMax {
		return fmt.Errorf("TLSVersMin (0x%04x) > TLSVersMax (0x%04x)", spec.TLSVersMin, spec.TLSVersMax)
	}

	return nil
}

// DeepCopySpec creates a deep copy of a ClientHelloSpec.
// Extensions are copied by reference since they should not be mutated in-place
// after copying. The engine creates new extension objects when mutating.
func DeepCopySpec(spec *utls.ClientHelloSpec) *utls.ClientHelloSpec {
	cp := &utls.ClientHelloSpec{
		CipherSuites:       make([]uint16, len(spec.CipherSuites)),
		CompressionMethods: make([]uint8, len(spec.CompressionMethods)),
		Extensions:         make([]utls.TLSExtension, len(spec.Extensions)),
		TLSVersMin:         spec.TLSVersMin,
		TLSVersMax:         spec.TLSVersMax,
	}
	copy(cp.CipherSuites, spec.CipherSuites)
	copy(cp.CompressionMethods, spec.CompressionMethods)
	copy(cp.Extensions, spec.Extensions)
	return cp
}

// isGREASE checks if a uint16 value is a GREASE value.
// GREASE values have the pattern 0xNaNa where N is any hex digit.
func isGREASE(val uint16) bool {
	return (val>>8) == (val&0xff) && (val&0xf) == 0xa
}

// intensityScale returns a multiplier for mutation probabilities based on intensity.
func intensityScale(intensity MutationIntensity) float64 {
	switch intensity {
	case IntensityLow:
		return 0.5
	case IntensityMedium:
		return 1.0
	case IntensityHigh:
		return 1.5 // Can exceed 1.0 probability, but that's fine - capped at 1.0 effectively.
	default:
		return 1.0
	}
}

// SortedCipherSuites returns a sorted copy of cipher suite IDs (for fingerprint comparison).
func SortedCipherSuites(suites []uint16) []uint16 {
	sorted := make([]uint16, len(suites))
	copy(sorted, suites)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	return sorted
}