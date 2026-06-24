package engine

import (
	"math/rand"
	"testing"

	utls "github.com/refraction-networking/utls"
)

func TestEngineMutate(t *testing.T) {
	// Setup deterministic RNG and default config
	rng := rand.New(rand.NewSource(42))
	cfg := MutationConfig{
		ExtensionShuffleProbability:       1.0,
		CipherShuffleProbability:          1.0,
		CipherSubsetProbability:           0.5,
		SupportedGroupsShuffleProbability: 1.0,
		ALPNShuffleProbability:            1.0,
		GREASEMutationProbability:         1.0,
		PaddingMutationProbability:        0.0,
	}

	engine := NewEngine(cfg)

	// Create a base spec
	spec := &utls.ClientHelloSpec{
		TLSVersMin: utls.VersionTLS12,
		TLSVersMax: utls.VersionTLS13,
		CipherSuites: []uint16{
			utls.TLS_AES_128_GCM_SHA256,
			utls.TLS_CHACHA20_POLY1305_SHA256,
			utls.TLS_AES_256_GCM_SHA384,
		},
		Extensions: []utls.TLSExtension{
			&utls.SNIExtension{ServerName: "example.com"},
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{utls.X25519, utls.CurveP256}},
			&utls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
		},
	}

	// Mutate high intensity
	mutated := engine.Mutate(spec, rng, IntensityHigh)

	if len(mutated.CipherSuites) == 0 {
		t.Errorf("Mutated spec should have cipher suites")
	}

	if len(mutated.Extensions) == 0 {
		t.Errorf("Mutated spec should have extensions")
	}

	// Ensure SNI is still first or present (SNI should always be 0th if present)
	if _, ok := mutated.Extensions[0].(*utls.SNIExtension); !ok {
		// Sometimes GREASE gets inserted at 0, check if SNI is at least there
		hasSNI := false
		for _, ext := range mutated.Extensions {
			if _, isSNI := ext.(*utls.SNIExtension); isSNI {
				hasSNI = true
				break
			}
		}
		if !hasSNI {
			t.Errorf("Mutated spec lost SNI extension")
		}
	}
}


