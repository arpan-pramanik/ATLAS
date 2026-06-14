package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"strings"
	"time"

	"atlas/atlas/internal/config"
	"atlas/atlas/internal/controller"
	"atlas/atlas/internal/engine"
	"atlas/atlas/internal/genome"

	"github.com/jessevdk/go-flags"
	utls "github.com/refraction-networking/utls"
	"github.com/sirupsen/logrus"
)

// Options holds the command-line options.
type Options struct {
	Listen       string `short:"l" long:"listen" description:"Listen address" default:":1080"`
	CertFile     string `short:"c" long:"cert-file" description:"Path to MITM certificate file" default:"mitm-cert.pem"`
	KeyFile      string `short:"k" long:"key-file" description:"Path to MITM key file" default:"mitm-key.pem"`
	ConfigFile   string `short:"C" long:"config" description:"Path to config file"`
	LogLevel     string `short:"L" long:"log-level" description:"Log level (debug, info, warn, error)" default:"info"`
	GenerateCert bool   `long:"generate-cert" description:"Generate a new MITM certificate and key"`
}

// MITM CA certificate template.
func generateMITMCA(certFile, keyFile string) error {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"ATLAS Proxy"},
			CommonName:   "ATLAS MITM CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	keyFileOut, err := createOrOpenFile(keyFile)
	if err != nil {
		return err
	}
	defer keyFileOut.Close()
	keyBlock := pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}
	if err := pem.Encode(keyFileOut, &keyBlock); err != nil {
		return fmt.Errorf("failed to write key file: %w", err)
	}

	certFileOut, err := createOrOpenFile(certFile)
	if err != nil {
		return err
	}
	defer certFileOut.Close()
	certBlock := pem.Block{Type: "CERTIFICATE", Bytes: derBytes}
	if err := pem.Encode(certFileOut, &certBlock); err != nil {
		return fmt.Errorf("failed to write cert file: %w", err)
	}

	return nil
}

func createOrOpenFile(filename string) (*os.File, error) {
	if _, err := os.Stat(filename); err == nil {
		return os.OpenFile(filename, os.O_WRONLY|os.O_TRUNC, 0600)
	} else if os.IsNotExist(err) {
		return os.Create(filename)
	} else {
		return nil, err
	}
}

func main() {
	var opts Options
	parser := flags.NewParser(&opts, flags.Default)
	_, err := parser.Parse()
	if err != nil {
		if flagsErr, ok := err.(*flags.Error); !ok || flagsErr.Type != flags.ErrHelp {
			logrus.Fatalf("Failed to parse arguments: %v", err)
		}
		return
	}

	// Set log level.
	level, err := logrus.ParseLevel(opts.LogLevel)
	if err != nil {
		logrus.Fatalf("Invalid log level: %v", err)
	}
	logrus.SetLevel(level)

	// Generate cert if requested.
	if opts.GenerateCert {
		if err := generateMITMCA(opts.CertFile, opts.KeyFile); err != nil {
			logrus.Fatalf("Failed to generate MITM certificate: %v", err)
		}
		logrus.Infof("Generated MITM certificate and key at %s and %s", opts.CertFile, opts.KeyFile)
		return
	}

	// Load configuration.
	cfg, err := config.LoadConfig(opts.ConfigFile)
	if err != nil {
		logrus.Fatalf("Failed to load config: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		logrus.Fatalf("Invalid config: %v", err)
	}

	// Override log level if set in config and not passed via CLI (basic merge logic)
	if opts.LogLevel == "info" && cfg.LogLevel != "" {
		if lvl, err := logrus.ParseLevel(cfg.LogLevel); err == nil {
			logrus.SetLevel(lvl)
		}
	}

	// Generate master seed for the genome.
	seedSource := genome.SeedCryptoRand
	if cfg.Seed.Source == "system" {
		seedSource = genome.SeedSystem
	} else if cfg.Seed.Source == "cloudflare" {
		seedSource = genome.SeedCloudflare
	} else if cfg.Seed.Source == "qrng" {
		seedSource = genome.SeedQRNG
	}
	masterSeed, err := genome.GenerateSeed(seedSource)
	if err != nil {
		logrus.Fatalf("Failed to generate genome seed: %v", err)
	}
	logrus.Infof("Generated master seed from %s", cfg.Seed.Source)

	engineCfg := engine.MutationConfig{
		ExtensionShuffleProbability:       cfg.Mutation.ExtensionShuffle,
		CipherShuffleProbability:          cfg.Mutation.CipherShuffle,
		CipherSubsetProbability:           cfg.Mutation.CipherSubset,
		SupportedGroupsShuffleProbability: cfg.Mutation.SupportedGroupsShuffle,
		ALPNShuffleProbability:            cfg.Mutation.ALPNShuffle,
		GREASEMutationProbability:         cfg.Mutation.GREASEMutation,
		PaddingMutationProbability:        cfg.Mutation.PaddingMutation,
	}

	// Initialize the Adaptive Controller.
	ctrl, err := controller.NewAdaptiveController(
		masterSeed,
		engineCfg,
		cfg.Controller,
		cfg.Profiles,
	)
	if err != nil {
		logrus.Fatalf("Failed to initialize controller: %v", err)
	}
	logrus.Infof("Adaptive Controller initialized with %d profiles", len(cfg.Profiles))

	// Load MITM certificate and key.
	cert, err := tls.LoadX509KeyPair(opts.CertFile, opts.KeyFile)
	if err != nil {
		logrus.Fatalf("Failed to load MITM certificate: %v", err)
	}

	listenAddr := opts.Listen
	if cfg.Proxy.Listen != "" && opts.Listen == ":1080" {
		listenAddr = cfg.Proxy.Listen
	}

	// Start listening.
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		logrus.Fatalf("Failed to listen on %s: %v", listenAddr, err)
	}
	defer listener.Close()

	logrus.Infof("ATLAS proxy listening on %s", listenAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			logrus.Errorf("Failed to accept connection: %v", err)
			continue
		}
		go handleClient(conn, cert, ctrl)
	}
}

func handleClient(clientConn net.Conn, mitmCert tls.Certificate, ctrl *controller.AdaptiveController) {
	defer clientConn.Close()

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{mitmCert},
		MinVersion:   tls.VersionTLS12,
	}

	tlsConn := tls.Server(clientConn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		logrus.Errorf("TLS handshake with client failed: %v", err)
		return
	}
	defer tlsConn.Close()

	buf := make([]byte, 4096)
	n, err := tlsConn.Read(buf)
	if err != nil {
		logrus.Errorf("Failed to read HTTP request: %v", err)
		return
	}
	reqBytes := buf[:n]

	reqLine := strings.SplitN(string(reqBytes), " ", 3)
	if len(reqLine) < 3 || reqLine[0] != "CONNECT" {
		logrus.Warnf("Expected CONNECT request, got: %s", string(reqBytes))
		return
	}

	hostPort := strings.TrimSpace(reqLine[1])
	host, portStr, err := net.SplitHostPort(hostPort)
	if err != nil {
		host = hostPort
		portStr = "443"
	}
	port := portStr
	if port == "" {
		port = "443"
	}
	target := net.JoinHostPort(host, port)

	logrus.Debugf("Client wants to connect to %s via CONNECT", target)

	targetConn, err := net.Dial("tcp", target)
	if err != nil {
		logrus.Errorf("Failed to dial target %s: %v", target, err)
		tlsConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer targetConn.Close()

	// Get the mutated ClientHello from the Adaptive Controller.
	spec, profileName, jitter, fp, err := ctrl.NextSpec(host)
	if err != nil {
		logrus.Errorf("Failed to get NextSpec from controller: %v", err)
		targetConn.Close()
		tlsConn.Write([]byte("HTTP/1.1 500 Internal Server Error\r\n\r\n"))
		return
	}

	// Apply timing jitter to disrupt behavioral analysis.
	if jitter > 0 {
		time.Sleep(jitter)
	}

	// Create uTLS connection.
	uConn := utls.UClient(targetConn, &utls.Config{ServerName: host}, utls.HelloCustom)

	// Apply the mutated spec.
	if err := uConn.ApplyPreset(spec); err != nil {
		logrus.Errorf("Failed to apply preset: %v", err)
		targetConn.Close()
		tlsConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}

	// Perform handshake and measure RTT.
	start := time.Now()
	err = uConn.Handshake()
	rtt := time.Since(start)
	success := (err == nil)

	// Record the outcome for the Adaptive Controller.
	ctrl.RecordResult(profileName, fp.JA3Hash, fp.JA4Hash, rtt, success)

	if !success {
		logrus.Errorf("TLS handshake to target failed (Profile: %s, RTT: %v): %v", profileName, rtt, err)
		targetConn.Close()
		tlsConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}

	// Tunnel established.
	if _, err := tlsConn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
		logrus.Errorf("Failed to write proxy response: %v", err)
		return
	}

	logrus.Infof("Established tunnel to %s (Profile: %s, Gen: %d, JA3: %s)", target, profileName, ctrl.GetGeneration(), fp.JA3Hash[:8])

	// Relay data.
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(tlsConn, uConn)
		tlsConn.Close()
		uConn.Close()
		done <- struct{}{}
	}()
	go func() {
		io.Copy(uConn, tlsConn)
		tlsConn.Close()
		uConn.Close()
		done <- struct{}{}
	}()

	<-done // Wait for one side to close.
}