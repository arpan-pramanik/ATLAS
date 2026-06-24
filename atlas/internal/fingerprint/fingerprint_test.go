package fingerprint

import (
	"testing"

	utls "github.com/refraction-networking/utls"
)

func TestExtract(t *testing.T) {
	spec := &utls.ClientHelloSpec{
		TLSVersMin: utls.VersionTLS12,
		TLSVersMax: utls.VersionTLS13,
		CipherSuites: []uint16{
			utls.GREASE_PLACEHOLDER,
			utls.TLS_AES_128_GCM_SHA256,
			utls.TLS_CHACHA20_POLY1305_SHA256,
		},
		CompressionMethods: []uint8{0},
		Extensions: []utls.TLSExtension{
			&utls.UtlsGREASEExtension{},
			&utls.SNIExtension{ServerName: "example.com"},
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{utls.CurveID(utls.GREASE_PLACEHOLDER), utls.X25519, utls.CurveP256}},
			&utls.SupportedPointsExtension{SupportedPoints: []byte{0}},
		},
	}

	result := Extract(spec)

	if result.JA3Hash == "" {
		t.Errorf("JA3Hash should not be empty")
	}
	if result.JA4Hash == "" {
		t.Errorf("JA4Hash should not be empty")
	}

	// Cipher suite extraction should skip GREASE
	if len(result.CipherSuiteIDs) != 2 {
		t.Errorf("Expected 2 cipher suites, got %d", len(result.CipherSuiteIDs))
	}
	if result.CipherSuiteIDs[0] != utls.TLS_AES_128_GCM_SHA256 {
		t.Errorf("Expected first cipher suite to be TLS_AES_128_GCM_SHA256")
	}

	// Extension extraction should skip GREASE
	if len(result.ExtensionIDs) != 3 && len(result.ExtensionIDs) != 4 {
		t.Errorf("Expected 3 or 4 extensions, got %d", len(result.ExtensionIDs))
	}

	if len(result.JA4Hash) < 34 {
		t.Errorf("JA4Hash format seems incorrect: %s", result.JA4Hash)
	}
}

func TestIsGREASE(t *testing.T) {
	if !isGREASE(0x0a0a) {
		t.Errorf("0x0a0a should be considered GREASE")
	}
	if !isGREASE(0x1a1a) {
		t.Errorf("0x1a1a should be considered GREASE")
	}
	if isGREASE(0x1301) {
		t.Errorf("0x1301 should not be considered GREASE")
	}
	if isGREASE(0x0000) {
		t.Errorf("0x0000 should not be considered GREASE")
	}
}
