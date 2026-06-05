// Package genome implements the evolutionary lineage concept for ATLAS TLS fingerprints.
// It tracks how fingerprints evolve over time through generations, providing
// reproducible mutation via seeded PRNG and lineage tracking for analysis.
package genome

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"time"

	log "github.com/sirupsen/logrus"
)

// SeedSource identifies the entropy source used for seed generation.
type SeedSource string

const (
	// SeedCryptoRand uses Go's crypto/rand for cryptographically secure randomness.
	SeedCryptoRand SeedSource = "crypto"
	// SeedSystem mixes /dev/urandom with system state (time, PID) for additional entropy.
	SeedSystem SeedSource = "system"
	// SeedCloudflare uses Cloudflare's drand randomness beacon (lava lamps) mixed with local entropy.
	SeedCloudflare SeedSource = "cloudflare"
	// SeedQRNG is a placeholder for quantum random number generator support.
	SeedQRNG SeedSource = "qrng"
)

// seedSize is the standard seed length in bytes (256-bit).
const seedSize = 32

// GenerateSeed produces a 32-byte (256-bit) high-entropy seed from the specified source.
// All seed sources produce cryptographically suitable output.
func GenerateSeed(source SeedSource) ([]byte, error) {
	switch source {
	case SeedCryptoRand:
		return generateCryptoSeed()
	case SeedSystem:
		return generateSystemSeed()
	case SeedCloudflare:
		return generateCloudflareSeed()
	case SeedQRNG:
		log.Warn("QRNG not available, falling back to crypto/rand")
		return generateCryptoSeed()
	default:
		return nil, fmt.Errorf("unknown seed source: %q", source)
	}
}

// generateCryptoSeed reads 32 bytes from crypto/rand.
func generateCryptoSeed() ([]byte, error) {
	seed := make([]byte, seedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("crypto/rand read failed: %w", err)
	}
	return seed, nil
}

// generateSystemSeed mixes /dev/urandom data with the current time and PID,
// then hashes the mixture with SHA-256 to produce a 32-byte seed.
func generateSystemSeed() ([]byte, error) {
	// Read 32 bytes from /dev/urandom.
	urandom, err := os.Open("/dev/urandom")
	if err != nil {
		return nil, fmt.Errorf("failed to open /dev/urandom: %w", err)
	}
	defer urandom.Close()

	urandomBytes := make([]byte, seedSize)
	if _, err := io.ReadFull(urandom, urandomBytes); err != nil {
		return nil, fmt.Errorf("failed to read /dev/urandom: %w", err)
	}

	// Mix in time nanos and PID for extra entropy diversity.
	timeBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(timeBytes, uint64(time.Now().UnixNano()))

	pidBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(pidBytes, uint32(os.Getpid()))

	// Concatenate all entropy sources and hash.
	mixture := make([]byte, 0, len(urandomBytes)+len(timeBytes)+len(pidBytes))
	mixture = append(mixture, urandomBytes...)
	mixture = append(mixture, timeBytes...)
	mixture = append(mixture, pidBytes...)

	hash := sha256.Sum256(mixture)
	return hash[:], nil
}

// generateCloudflareSeed fetches high-entropy randomness from Cloudflare's drand beacon
// (powered in part by their lava lamp wall) and mixes it with local crypto/rand.
// This ensures global high entropy combined with device-level uniqueness.
func generateCloudflareSeed() ([]byte, error) {
	// 1. Fetch Cloudflare drand randomness.
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("https://drand.cloudflare.com/public/latest")
	if err != nil {
		log.Warnf("drand fetch failed: %v. Falling back to local high-entropy heuristic.", err)
		return generateLocalHighEntropySeed()
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Warnf("drand returned status %d. Falling back to local high-entropy heuristic.", resp.StatusCode)
		return generateLocalHighEntropySeed()
	}

	var drandResp struct {
		Randomness string `json:"randomness"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&drandResp); err != nil {
		return nil, fmt.Errorf("failed to decode drand response: %w", err)
	}

	cfEntropy, err := hex.DecodeString(drandResp.Randomness)
	if err != nil {
		return nil, fmt.Errorf("failed to decode drand hex: %w", err)
	}

	// 2. Fetch local crypto/rand randomness.
	localEntropy, err := generateCryptoSeed()
	if err != nil {
		return nil, fmt.Errorf("local crypto/rand failed: %w", err)
	}

	// 3. Mix them together and hash to guarantee exactly 32 bytes and uniform distribution.
	mixture := make([]byte, 0, len(cfEntropy)+len(localEntropy))
	mixture = append(mixture, cfEntropy...)
	mixture = append(mixture, localEntropy...)

	hash := sha256.Sum256(mixture)
	log.Infof("Successfully fetched Cloudflare randomness and mixed with local entropy")
	return hash[:], nil
}

// generateLocalHighEntropySeed acts as a close-to-drand fallback if internet is unavailable.
// It combines /dev/urandom, CPU execution time jitter, and raw memory statistics.
func generateLocalHighEntropySeed() ([]byte, error) {
	// 1. Base crypto/rand entropy
	baseEntropy, err := generateCryptoSeed()
	if err != nil {
		return nil, err
	}

	// 2. CPU execution time jitter
	var jitter int64
	for i := 0; i < 1000; i++ {
		jitter += time.Now().UnixNano() % 100
	}
	jitterBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(jitterBytes, uint64(jitter))

	// 3. Hardware / Memory Statistics
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	memBytes := make([]byte, 32)
	binary.LittleEndian.PutUint64(memBytes[0:8], memStats.Alloc)
	binary.LittleEndian.PutUint64(memBytes[8:16], memStats.Sys)
	binary.LittleEndian.PutUint64(memBytes[16:24], memStats.Mallocs)
	binary.LittleEndian.PutUint64(memBytes[24:32], memStats.Frees)

	// Combine and hash
	mixture := make([]byte, 0, len(baseEntropy)+len(jitterBytes)+len(memBytes))
	mixture = append(mixture, baseEntropy...)
	mixture = append(mixture, jitterBytes...)
	mixture = append(mixture, memBytes...)

	hash := sha256.Sum256(mixture)
	log.Infof("Successfully generated local high-entropy heuristic seed (drand fallback)")
	return hash[:], nil
}

// SeedFromBytes normalizes arbitrary input bytes to a 32-byte seed via SHA-256.
// This allows any data (passwords, keys, previous seeds) to be used as a genome seed.
func SeedFromBytes(b []byte) []byte {
	hash := sha256.Sum256(b)
	return hash[:]
}
