package config

import (
	"fmt"
	"math/rand"

	utls "github.com/refraction-networking/utls"
)

// allProfileNames is the canonical list of available profile names.
var allProfileNames = []string{"chrome", "firefox", "safari", "randomized"}

// AllProfileNames returns the list of all available TLS profile names.
func AllProfileNames() []string {
	out := make([]string, len(allProfileNames))
	copy(out, allProfileNames)
	return out
}

// GetProfileByName returns a ClientHelloSpec for the given profile name.
// The "randomized" profile requires a non-nil rng; all others ignore it.
func GetProfileByName(name string, rng *rand.Rand) (*utls.ClientHelloSpec, error) {
	switch name {
	case "chrome":
		return ChromeProfile(), nil
	case "firefox":
		return FirefoxProfile(), nil
	case "safari":
		return SafariProfile(), nil
	case "randomized":
		if rng == nil {
			return nil, fmt.Errorf("profiles: rng must not be nil for randomized profile")
		}
		return RandomizedProfile(rng), nil
	default:
		return nil, fmt.Errorf("profiles: unknown profile %q", name)
	}
}

// ChromeProfile returns a ClientHelloSpec resembling Chrome 120+.
//
// Characteristics:
//   - TLS 1.2–1.3
//   - GREASE at start of cipher suites and extensions
//   - TLS 1.3 ciphers (AES-128-GCM, AES-256-GCM, ChaCha20) + TLS 1.2 ciphers
//   - X25519, P-256, P-384 curves
//   - ALPN: h2, http/1.1
//   - Extensions: SNI, extended_master_secret, renegotiation_info,
//     supported_groups, ec_point_formats, session_ticket, ALPN,
//     status_request, signature_algorithms, signed_cert_timestamp,
//     key_share, psk_key_exchange_modes, supported_versions,
//     compress_certificate, application_settings, padding
func ChromeProfile() *utls.ClientHelloSpec {
	return &utls.ClientHelloSpec{
		TLSVersMin: utls.VersionTLS12,
		TLSVersMax: utls.VersionTLS13,
		CipherSuites: []uint16{
			utls.GREASE_PLACEHOLDER,
			// TLS 1.3 cipher suites.
			0x1301, // TLS_AES_128_GCM_SHA256
			0x1302, // TLS_AES_256_GCM_SHA384
			0x1303, // TLS_CHACHA20_POLY1305_SHA256
			// TLS 1.2 cipher suites.
			0xc02b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
			0xc02f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
			0xc02c, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
			0xc030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
			0xcca9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
			0xcca8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
		},
		CompressionMethods: []uint8{0x00}, // null compression
		Extensions: []utls.TLSExtension{
			&utls.UtlsGREASEExtension{},
			&utls.SNIExtension{}, // ServerName set per-connection
			&utls.ExtendedMasterSecretExtension{},
			&utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateOnceAsClient},
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{
				utls.GREASE_PLACEHOLDER,
				utls.X25519,
				utls.CurveP256,
				utls.CurveP384,
			}},
			&utls.SupportedPointsExtension{SupportedPoints: []uint8{0x00}}, // uncompressed
			&utls.SessionTicketExtension{},
			&utls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
			&utls.StatusRequestExtension{},
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256,
				utls.PSSWithSHA256,
				utls.PKCS1WithSHA256,
				utls.ECDSAWithP384AndSHA384,
				utls.PSSWithSHA384,
				utls.PKCS1WithSHA384,
				utls.PSSWithSHA512,
				utls.PKCS1WithSHA512,
			}},
			&utls.SCTExtension{},
			&utls.KeyShareExtension{KeyShares: []utls.KeyShare{
				{Group: utls.GREASE_PLACEHOLDER, Data: []byte{0}},
				{Group: utls.X25519},
			}},
			&utls.PSKKeyExchangeModesExtension{Modes: []uint8{
				1, // psk_dhe_ke
			}},
			&utls.SupportedVersionsExtension{Versions: []uint16{
				utls.GREASE_PLACEHOLDER,
				utls.VersionTLS13,
				utls.VersionTLS12,
			}},
			&utls.UtlsCompressCertExtension{Algorithms: []utls.CertCompressionAlgo{
				utls.CertCompressionBrotli,
			}},
			&utls.ApplicationSettingsExtension{SupportedProtocols: []string{"h2"}},
			&utls.UtlsGREASEExtension{},
			&utls.UtlsPaddingExtension{GetPaddingLen: utls.BoringPaddingStyle},
		},
	}
}

// FirefoxProfile returns a ClientHelloSpec resembling Firefox 120+.
//
// Characteristics:
//   - TLS 1.2–1.3
//   - No GREASE (Firefox does not use GREASE)
//   - TLS 1.3 + TLS 1.2 cipher suites in Firefox order
//   - X25519, P-256, P-384, P-521 curves
//   - ALPN: h2, http/1.1
func FirefoxProfile() *utls.ClientHelloSpec {
	return &utls.ClientHelloSpec{
		TLSVersMin: utls.VersionTLS12,
		TLSVersMax: utls.VersionTLS13,
		CipherSuites: []uint16{
			// TLS 1.3 cipher suites.
			0x1301, // TLS_AES_128_GCM_SHA256
			0x1303, // TLS_CHACHA20_POLY1305_SHA256
			0x1302, // TLS_AES_256_GCM_SHA384
			// TLS 1.2 cipher suites.
			0xc02b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
			0xc02f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
			0xcca9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
			0xcca8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
			0xc02c, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
			0xc030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
			0xc00a, // TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
			0xc009, // TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
			0xc013, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
			0xc014, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
		},
		CompressionMethods: []uint8{0x00},
		Extensions: []utls.TLSExtension{
			&utls.SNIExtension{},
			&utls.ExtendedMasterSecretExtension{},
			&utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateOnceAsClient},
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{
				utls.X25519,
				utls.CurveP256,
				utls.CurveP384,
				utls.CurveP521,
			}},
			&utls.SupportedPointsExtension{SupportedPoints: []uint8{0x00}},
			&utls.SessionTicketExtension{},
			&utls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
			&utls.StatusRequestExtension{},
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256,
				utls.ECDSAWithP384AndSHA384,
				utls.ECDSAWithP521AndSHA512,
				utls.PSSWithSHA256,
				utls.PSSWithSHA384,
				utls.PSSWithSHA512,
				utls.PKCS1WithSHA256,
				utls.PKCS1WithSHA384,
				utls.PKCS1WithSHA512,
			}},
			&utls.SCTExtension{},
			&utls.KeyShareExtension{KeyShares: []utls.KeyShare{
				{Group: utls.X25519},
				{Group: utls.CurveP256},
			}},
			&utls.PSKKeyExchangeModesExtension{Modes: []uint8{1}},
			&utls.SupportedVersionsExtension{Versions: []uint16{
				utls.VersionTLS13,
				utls.VersionTLS12,
			}},
			&utls.UtlsCompressCertExtension{Algorithms: []utls.CertCompressionAlgo{
				utls.CertCompressionZlib,
				utls.CertCompressionBrotli,
			}},
			&utls.UtlsPaddingExtension{GetPaddingLen: utls.BoringPaddingStyle},
		},
	}
}

// SafariProfile returns a ClientHelloSpec resembling Safari (macOS/iOS).
//
// Characteristics:
//   - TLS 1.2–1.3
//   - GREASE
//   - Narrower cipher suite set
//   - P-256, P-384, P-521, X25519 curves (P-256 first, unlike Chrome)
//   - ALPN: h2, http/1.1
func SafariProfile() *utls.ClientHelloSpec {
	return &utls.ClientHelloSpec{
		TLSVersMin: utls.VersionTLS12,
		TLSVersMax: utls.VersionTLS13,
		CipherSuites: []uint16{
			utls.GREASE_PLACEHOLDER,
			// TLS 1.3 cipher suites.
			0x1301, // TLS_AES_128_GCM_SHA256
			0x1302, // TLS_AES_256_GCM_SHA384
			0x1303, // TLS_CHACHA20_POLY1305_SHA256
			// TLS 1.2 cipher suites.
			0xc02c, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
			0xc02b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
			0xc030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
			0xc02f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
			0xcca9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
			0xcca8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
		},
		CompressionMethods: []uint8{0x00},
		Extensions: []utls.TLSExtension{
			&utls.UtlsGREASEExtension{},
			&utls.SNIExtension{},
			&utls.ExtendedMasterSecretExtension{},
			&utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateOnceAsClient},
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{
				utls.GREASE_PLACEHOLDER,
				utls.CurveP256,
				utls.CurveP384,
				utls.CurveP521,
				utls.X25519,
			}},
			&utls.SupportedPointsExtension{SupportedPoints: []uint8{0x00}},
			&utls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
			&utls.StatusRequestExtension{},
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256,
				utls.ECDSAWithP384AndSHA384,
				utls.ECDSAWithP521AndSHA512,
				utls.PSSWithSHA256,
				utls.PSSWithSHA384,
				utls.PSSWithSHA512,
				utls.PKCS1WithSHA256,
				utls.PKCS1WithSHA384,
				utls.PKCS1WithSHA512,
			}},
			&utls.SCTExtension{},
			&utls.KeyShareExtension{KeyShares: []utls.KeyShare{
				{Group: utls.GREASE_PLACEHOLDER, Data: []byte{0}},
				{Group: utls.X25519},
			}},
			&utls.PSKKeyExchangeModesExtension{Modes: []uint8{1}},
			&utls.SupportedVersionsExtension{Versions: []uint16{
				utls.GREASE_PLACEHOLDER,
				utls.VersionTLS13,
				utls.VersionTLS12,
			}},
			&utls.UtlsCompressCertExtension{Algorithms: []utls.CertCompressionAlgo{
				utls.CertCompressionZlib,
			}},
			&utls.SessionTicketExtension{},
			&utls.UtlsGREASEExtension{},
			&utls.UtlsPaddingExtension{GetPaddingLen: utls.BoringPaddingStyle},
		},
	}
}

// RandomizedProfile generates a random-but-valid ClientHelloSpec by
// picking random subsets and orderings of cipher suites, curves, signature
// algorithms, and extensions. The resulting fingerprint is unique on each
// call but structurally valid for TLS 1.2/1.3 negotiation.
func RandomizedProfile(rng *rand.Rand) *utls.ClientHelloSpec {
	// --- Cipher suites: always include all TLS 1.3 suites, then pick a random
	// subset + order of TLS 1.2 suites.
	tls13Ciphers := []uint16{0x1301, 0x1302, 0x1303}

	tls12Pool := []uint16{
		0xc02b, 0xc02f, 0xc02c, 0xc030,
		0xcca9, 0xcca8,
		0xc00a, 0xc009, 0xc013, 0xc014,
	}
	// Shuffle the TLS 1.2 pool and take at least 3 suites.
	rng.Shuffle(len(tls12Pool), func(i, j int) {
		tls12Pool[i], tls12Pool[j] = tls12Pool[j], tls12Pool[i]
	})
	count := 3 + rng.Intn(len(tls12Pool)-2) // at least 3
	if count > len(tls12Pool) {
		count = len(tls12Pool)
	}
	tls12Selected := tls12Pool[:count]

	ciphers := make([]uint16, 0, len(tls13Ciphers)+count+1)
	// 50% chance of leading GREASE.
	if rng.Float64() < 0.5 {
		ciphers = append(ciphers, utls.GREASE_PLACEHOLDER)
	}
	// Shuffle TLS 1.3 order.
	rng.Shuffle(len(tls13Ciphers), func(i, j int) {
		tls13Ciphers[i], tls13Ciphers[j] = tls13Ciphers[j], tls13Ciphers[i]
	})
	ciphers = append(ciphers, tls13Ciphers...)
	ciphers = append(ciphers, tls12Selected...)

	// --- Curves: always X25519 and P-256, optionally P-384 and P-521.
	curves := []utls.CurveID{utls.X25519, utls.CurveP256}
	if rng.Float64() < 0.7 {
		curves = append(curves, utls.CurveP384)
	}
	if rng.Float64() < 0.3 {
		curves = append(curves, utls.CurveP521)
	}
	rng.Shuffle(len(curves), func(i, j int) {
		curves[i], curves[j] = curves[j], curves[i]
	})
	// 50% chance of GREASE prefix.
	if rng.Float64() < 0.5 {
		curves = append([]utls.CurveID{utls.GREASE_PLACEHOLDER}, curves...)
	}

	// --- Signature algorithms: always include at least ECDSA-P256 and PSS-SHA256.
	sigAlgs := []utls.SignatureScheme{
		utls.ECDSAWithP256AndSHA256,
		utls.PSSWithSHA256,
		utls.PKCS1WithSHA256,
	}
	optionalSigAlgs := []utls.SignatureScheme{
		utls.ECDSAWithP384AndSHA384,
		utls.ECDSAWithP521AndSHA512,
		utls.PSSWithSHA384,
		utls.PSSWithSHA512,
		utls.PKCS1WithSHA384,
		utls.PKCS1WithSHA512,
	}
	for _, sa := range optionalSigAlgs {
		if rng.Float64() < 0.6 {
			sigAlgs = append(sigAlgs, sa)
		}
	}
	rng.Shuffle(len(sigAlgs), func(i, j int) {
		sigAlgs[i], sigAlgs[j] = sigAlgs[j], sigAlgs[i]
	})

	// --- Key shares: always X25519, optionally P-256.
	keyShares := []utls.KeyShare{{Group: utls.X25519}}
	if rng.Float64() < 0.4 {
		keyShares = append(keyShares, utls.KeyShare{Group: utls.CurveP256})
	}
	// 50% chance of GREASE key share at front.
	if rng.Float64() < 0.5 {
		keyShares = append([]utls.KeyShare{{Group: utls.GREASE_PLACEHOLDER, Data: []byte{0}}}, keyShares...)
	}

	// --- Supported versions.
	versions := []uint16{utls.VersionTLS13, utls.VersionTLS12}
	if rng.Float64() < 0.5 {
		versions = append([]uint16{utls.GREASE_PLACEHOLDER}, versions...)
	}

	// --- Build extensions list.
	exts := []utls.TLSExtension{
		&utls.SNIExtension{},
		&utls.ExtendedMasterSecretExtension{},
		&utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateOnceAsClient},
		&utls.SupportedCurvesExtension{Curves: curves},
		&utls.SupportedPointsExtension{SupportedPoints: []uint8{0x00}},
		&utls.SessionTicketExtension{},
		&utls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
		&utls.StatusRequestExtension{},
		&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: sigAlgs},
		&utls.SCTExtension{},
		&utls.KeyShareExtension{KeyShares: keyShares},
		&utls.PSKKeyExchangeModesExtension{Modes: []uint8{1}},
		&utls.SupportedVersionsExtension{Versions: versions},
	}

	// Optionally add compress_certificate.
	if rng.Float64() < 0.6 {
		algos := []utls.CertCompressionAlgo{utls.CertCompressionBrotli}
		if rng.Float64() < 0.4 {
			algos = append(algos, utls.CertCompressionZlib)
		}
		exts = append(exts, &utls.UtlsCompressCertExtension{Algorithms: algos})
	}

	// Optionally add application_settings.
	if rng.Float64() < 0.5 {
		exts = append(exts, &utls.ApplicationSettingsExtension{SupportedProtocols: []string{"h2"}})
	}

	// 50% chance of GREASE at start of extensions.
	if rng.Float64() < 0.5 {
		exts = append([]utls.TLSExtension{&utls.UtlsGREASEExtension{}}, exts...)
	}

	// Always add padding at the end.
	exts = append(exts, &utls.UtlsPaddingExtension{GetPaddingLen: utls.BoringPaddingStyle})

	return &utls.ClientHelloSpec{
		TLSVersMin:         utls.VersionTLS12,
		TLSVersMax:         utls.VersionTLS13,
		CipherSuites:       ciphers,
		CompressionMethods: []uint8{0x00},
		Extensions:         exts,
	}
}
