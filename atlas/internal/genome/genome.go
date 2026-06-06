// Package genome implements the evolutionary lineage concept for ATLAS TLS fingerprints.
//
// The core idea: fingerprint_N+1 = Mutate(fingerprint_N). The TLSGenome tracks the
// lineage of fingerprint generations, providing a seeded PRNG for reproducible
// mutation and a ring buffer of fingerprint hashes for auditing.
package genome

import (
	"encoding/binary"
	"math/rand"
	"sync"

	utls "github.com/refraction-networking/utls"
)

// maxLineageSize is the maximum number of fingerprint hashes retained in the lineage ring buffer.
const maxLineageSize = 100

// TLSGenome represents the evolutionary lineage of a TLS fingerprint.
// It tracks generations, maintains a seeded PRNG for reproducible mutations,
// and records a ring buffer of fingerprint hashes for lineage analysis.
type TLSGenome struct {
	seed       []byte                 // original 32-byte seed
	generation int                    // current generation counter
	current    *utls.ClientHelloSpec  // the current spec
	lineage    []string               // ring buffer of fingerprint hashes (last 100 generations)
	rng        *rand.Rand             // PRNG seeded from genome seed
	mu         sync.Mutex             // concurrency safety
}

// NewTLSGenome creates a new genome from the given seed and base ClientHelloSpec.
// The seed must be 32 bytes (use GenerateSeed or SeedFromBytes to produce one).
// Generation 0 is initialized with a deep copy of baseSpec.
func NewTLSGenome(seed []byte, baseSpec *utls.ClientHelloSpec) *TLSGenome {
	// Derive a deterministic PRNG seed from the first 8 bytes of the genome seed.
	var rngSeed int64
	if len(seed) >= 8 {
		rngSeed = int64(binary.LittleEndian.Uint64(seed[:8]))
	}

	return &TLSGenome{
		seed:       append([]byte{}, seed...), // defensive copy
		generation: 0,
		current:    DeepCopySpec(baseSpec),
		lineage:    make([]string, 0, maxLineageSize),
		rng:        rand.New(rand.NewSource(rngSeed)),
	}
}

// Generation returns the current generation number.
func (g *TLSGenome) Generation() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.generation
}

// CurrentSpec returns a deep copy of the current ClientHelloSpec.
// The caller may freely modify the returned spec without affecting the genome.
func (g *TLSGenome) CurrentSpec() *utls.ClientHelloSpec {
	g.mu.Lock()
	defer g.mu.Unlock()
	return DeepCopySpec(g.current)
}

// Evolve records the current fingerprint hash in the lineage, increments the
// generation counter, and returns the current spec. The actual mutation is
// applied externally by the engine - the genome just tracks the lineage.
func (g *TLSGenome) Evolve(fingerprintHash string) *utls.ClientHelloSpec {
	g.mu.Lock()
	defer g.mu.Unlock()

	// Append to the ring buffer, evicting the oldest entry if full.
	if len(g.lineage) >= maxLineageSize {
		// Shift left by one to make room (ring buffer behavior).
		copy(g.lineage, g.lineage[1:])
		g.lineage[len(g.lineage)-1] = fingerprintHash
	} else {
		g.lineage = append(g.lineage, fingerprintHash)
	}

	g.generation++

	return DeepCopySpec(g.current)
}

// SetCurrent updates the current spec. This is called by the engine after
// applying a mutation to install the new fingerprint into the genome.
func (g *TLSGenome) SetCurrent(spec *utls.ClientHelloSpec) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.current = DeepCopySpec(spec)
}

// GetLineage returns a copy of the lineage fingerprint hashes.
func (g *TLSGenome) GetLineage() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	result := make([]string, len(g.lineage))
	copy(result, g.lineage)
	return result
}

// Seed returns a copy of the genome's original seed.
func (g *TLSGenome) Seed() []byte {
	g.mu.Lock()
	defer g.mu.Unlock()
	result := make([]byte, len(g.seed))
	copy(result, g.seed)
	return result
}

// Rng returns the genome's seeded PRNG for use by mutation operations.
// The caller should hold appropriate locks if using the PRNG concurrently
// outside of TLSGenome methods.
func (g *TLSGenome) Rng() *rand.Rand {
	return g.rng
}

// DeepCopySpec creates a deep copy of a ClientHelloSpec.
// CipherSuites, CompressionMethods, and version fields are fully copied.
// Extensions are copied by reference - they should not be modified in place
// after being added to a spec. This is a pragmatic approach that avoids the
// complexity of serializing/deserializing every TLSExtension interface type.
func DeepCopySpec(spec *utls.ClientHelloSpec) *utls.ClientHelloSpec {
	if spec == nil {
		return nil
	}

	cp := &utls.ClientHelloSpec{
		CipherSuites:       append([]uint16{}, spec.CipherSuites...),
		CompressionMethods: append([]uint8{}, spec.CompressionMethods...),
		Extensions:         make([]utls.TLSExtension, len(spec.Extensions)),
		TLSVersMin:         spec.TLSVersMin,
		TLSVersMax:         spec.TLSVersMax,
	}

	// Copy extensions by reference - they should not be modified in place.
	copy(cp.Extensions, spec.Extensions)

	return cp
}
