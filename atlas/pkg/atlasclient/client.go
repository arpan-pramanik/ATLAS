package atlasclient

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"atlas/atlas/internal/config"
	"atlas/atlas/internal/controller"
	"atlas/atlas/internal/engine"
	"atlas/atlas/internal/genome"
	"atlas/atlas/internal/morphological"

	utls "github.com/refraction-networking/utls"
)

// AtlasClient wraps the standard http.Client and automatically evolves
// the TLS fingerprint for every outbound request using the Adaptive Controller.
type AtlasClient struct {
	*http.Client
	ctrl *controller.AdaptiveController
}

// New creates a new http.Client that uses the ATLAS evolutionary fingerprinting engine.
func New(cfg *config.Config) (*AtlasClient, error) {
	if cfg == nil {
		cfg = config.DefaultConfig()
	}

	// 1. Generate the initial high-entropy seed
	seedSource := genome.SeedCryptoRand
	if cfg.Seed.Source == "system" {
		seedSource = genome.SeedSystem
	} else if cfg.Seed.Source == "cloudflare" {
		seedSource = genome.SeedCloudflare
	}
	seed, err := genome.GenerateSeed(seedSource)
	if err != nil {
		return nil, fmt.Errorf("atlasclient: failed to generate seed: %w", err)
	}

	// 2. Map config
	engineCfg := engine.MutationConfig{
		ExtensionShuffleProbability:       cfg.Mutation.ExtensionShuffle,
		CipherShuffleProbability:          cfg.Mutation.CipherShuffle,
		CipherSubsetProbability:           cfg.Mutation.CipherSubset,
		SupportedGroupsShuffleProbability: cfg.Mutation.SupportedGroupsShuffle,
		ALPNShuffleProbability:            cfg.Mutation.ALPNShuffle,
		GREASEMutationProbability:         cfg.Mutation.GREASEMutation,
		PaddingMutationProbability:        cfg.Mutation.PaddingMutation,
	}

	// 3. Initialize Adaptive Controller
	ctrl, err := controller.NewAdaptiveController(
		seed,
		engineCfg,
		cfg.Controller,
		cfg.Profiles,
	)
	if err != nil {
		return nil, fmt.Errorf("atlasclient: failed to init controller: %w", err)
	}

	// 4. Build the custom Transport DialTLSContext
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	transport.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr
		}

		// Dial the raw TCP connection
		dialer := &net.Dialer{}
		rawConn, err := dialer.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}

		// Request the next evolved fingerprint from the controller
		start := time.Now()
		spec, profileName, delay, fp, err := ctrl.NextSpec(host)
		if err != nil {
			rawConn.Close()
			return nil, err
		}

		// Apply the behavioral timing jitter
		if delay > 0 {
			time.Sleep(delay)
		}

		// Establish the uTLS connection
		uConn := utls.UClient(rawConn, &utls.Config{ServerName: host}, utls.HelloCustom)
		if err := uConn.ApplyPreset(spec); err != nil {
			rawConn.Close()
			return nil, err
		}

		err = uConn.HandshakeContext(ctx)
		rtt := time.Since(start)

		// Record the result to close the feedback loop
		success := (err == nil)
		ctrl.RecordResult(profileName, fp.JA3Hash, fp.JA4Hash, rtt, success)

		if err != nil {
			rawConn.Close()
			return nil, err
		}

		return uConn, nil
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	return &AtlasClient{
		Client: client,
		ctrl:   ctrl,
	}, nil
}

// GetMetrics returns the current health and entropy metrics from the controller.
func (ac *AtlasClient) GetMetrics() morphological.Metrics {
	return ac.ctrl.GetMetrics()
}
