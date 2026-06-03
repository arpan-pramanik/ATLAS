// Package fingerprint computes JA3 and JA4-like TLS fingerprint hashes from
// utls.ClientHelloSpec structs. Unlike traditional fingerprinting that operates
// on wire captures, this module works directly on the in-memory specification,
// enabling fingerprint prediction before any network activity occurs.
package fingerprint

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	utls "github.com/refraction-networking/utls"
)

// FingerprintResult holds the computed fingerprint data for a ClientHelloSpec.
type FingerprintResult struct {
	// JA3Hash is the MD5 hex digest of the JA3 raw string.
	JA3Hash string
	// JA3Raw is the raw JA3 string before hashing:
	// TLSVersion,CipherSuites,Extensions,EllipticCurves,ECPointFormats
	JA3Raw string
	// JA4Hash is a simplified JA4-like fingerprint hash.
	JA4Hash string
	// CipherSuiteIDs lists the extracted (non-GREASE) cipher suite IDs.
	CipherSuiteIDs []uint16
	// ExtensionIDs lists the extracted (non-GREASE) extension IDs.
	ExtensionIDs []uint16
}

// isGREASE checks if a value is a GREASE (Generate Random Extensions And
// Sustain Extensibility) value. GREASE values have their high byte equal to
// their low byte, and the low nibble is 0xa.
// See: https://www.rfc-editor.org/rfc/rfc8701
func isGREASE(val uint16) bool {
	hi := byte(val >> 8)
	lo := byte(val)
	return hi == lo && (lo&0x0f) == 0x0a
}

// getExtensionID extracts the TLS extension type ID from a utls.TLSExtension
// by serializing it and reading the first 2 bytes (big-endian uint16).
func getExtensionID(ext utls.TLSExtension) (uint16, error) {
	length := ext.Len()
	if length == 0 {
		return 0, fmt.Errorf("zero length extension")
	}
	buf := make([]byte, length)
	_, err := ext.Read(buf)
	// utls extensions return io.EOF on successful complete read.
	if err != nil && err != io.EOF {
		return 0, fmt.Errorf("reading extension: %w", err)
	}
	if len(buf) < 2 {
		return 0, fmt.Errorf("extension too short: %d bytes", len(buf))
	}
	return binary.BigEndian.Uint16(buf[0:2]), nil
}

// Extract computes all fingerprints (JA3, JA4-like) from a ClientHelloSpec.
// Returns nil if spec is nil.
func Extract(spec *utls.ClientHelloSpec) *FingerprintResult {
	if spec == nil {
		return nil
	}

	result := &FingerprintResult{}

	// --- Collect non-GREASE cipher suites ---
	var cipherStrs []string
	for _, cs := range spec.CipherSuites {
		if isGREASE(cs) {
			continue
		}
		result.CipherSuiteIDs = append(result.CipherSuiteIDs, cs)
		cipherStrs = append(cipherStrs, strconv.FormatUint(uint64(cs), 10))
	}

	// --- Process extensions: collect IDs, curves, and point formats ---
	var (
		extStrs    []string
		curveStrs  []string
		pointStrs  []string
		hasSNI     bool
	)

	for _, ext := range spec.Extensions {
		// Extract the extension type ID by serializing.
		extID, err := getExtensionID(ext)
		if err != nil {
			// Skip extensions we cannot parse.
			continue
		}
		if isGREASE(extID) {
			continue
		}

		result.ExtensionIDs = append(result.ExtensionIDs, extID)
		extStrs = append(extStrs, strconv.FormatUint(uint64(extID), 10))

		// Check for SNI (extension type 0).
		if extID == 0 {
			hasSNI = true
		}

		// Extract elliptic curves from SupportedCurvesExtension.
		if sce, ok := ext.(*utls.SupportedCurvesExtension); ok {
			for _, curve := range sce.Curves {
				cid := uint16(curve)
				if isGREASE(cid) {
					continue
				}
				curveStrs = append(curveStrs, strconv.FormatUint(uint64(cid), 10))
			}
		}

		// Extract EC point formats from SupportedPointsExtension.
		if spe, ok := ext.(*utls.SupportedPointsExtension); ok {
			for _, pt := range spe.SupportedPoints {
				pointStrs = append(pointStrs, strconv.FormatUint(uint64(pt), 10))
			}
		}
	}

	// --- JA3 computation ---
	// Format: TLSVersion,CipherSuites,Extensions,EllipticCurves,ECPointFormats
	tlsVersionStr := strconv.FormatUint(uint64(spec.TLSVersMax), 10)

	ja3Parts := []string{
		tlsVersionStr,
		strings.Join(cipherStrs, "-"),
		strings.Join(extStrs, "-"),
		strings.Join(curveStrs, "-"),
		strings.Join(pointStrs, "-"),
	}
	result.JA3Raw = strings.Join(ja3Parts, ",")
	hash := md5.Sum([]byte(result.JA3Raw))
	result.JA3Hash = fmt.Sprintf("%x", hash)

	// --- JA4-like computation ---
	// Format: {protocol}{version}{sni}{cipherCount}{extCount}_{sortedCipherHash}_{sortedExtHash}
	protocol := "t"

	var versionTag string
	switch spec.TLSVersMax {
	case utls.VersionTLS13:
		versionTag = "13"
	case utls.VersionTLS12:
		versionTag = "12"
	case utls.VersionTLS11:
		versionTag = "11"
	case utls.VersionTLS10:
		versionTag = "10"
	default:
		versionTag = "00"
	}

	sniFlag := "i"
	if hasSNI {
		sniFlag = "d"
	}

	cipherCount := fmt.Sprintf("%02d", len(result.CipherSuiteIDs))
	extCount := fmt.Sprintf("%02d", len(result.ExtensionIDs))

	// Sorted cipher hash: sort non-GREASE cipher suite IDs ascending,
	// join with ",", SHA256, take first 12 hex chars.
	sortedCiphers := make([]uint16, len(result.CipherSuiteIDs))
	copy(sortedCiphers, result.CipherSuiteIDs)
	sort.Slice(sortedCiphers, func(i, j int) bool {
		return sortedCiphers[i] < sortedCiphers[j]
	})
	var sortedCipherParts []string
	for _, c := range sortedCiphers {
		sortedCipherParts = append(sortedCipherParts, strconv.FormatUint(uint64(c), 10))
	}
	cipherSHA := sha256.Sum256([]byte(strings.Join(sortedCipherParts, ",")))
	sortedCipherHash := fmt.Sprintf("%x", cipherSHA)[:12]

	// Sorted extension hash: sort non-GREASE extension IDs ascending,
	// join with ",", SHA256, take first 12 hex chars.
	sortedExts := make([]uint16, len(result.ExtensionIDs))
	copy(sortedExts, result.ExtensionIDs)
	sort.Slice(sortedExts, func(i, j int) bool {
		return sortedExts[i] < sortedExts[j]
	})
	var sortedExtParts []string
	for _, e := range sortedExts {
		sortedExtParts = append(sortedExtParts, strconv.FormatUint(uint64(e), 10))
	}
	extSHA := sha256.Sum256([]byte(strings.Join(sortedExtParts, ",")))
	sortedExtHash := fmt.Sprintf("%x", extSHA)[:12]

	result.JA4Hash = fmt.Sprintf("%s%s%s%s%s_%s_%s",
		protocol, versionTag, sniFlag, cipherCount, extCount,
		sortedCipherHash, sortedExtHash,
	)

	return result
}
