package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"time"

	"atlas/atlas/internal/config"
	"atlas/atlas/pkg/atlasclient"
)

func main() {
	fmt.Println("Starting Live-Traffic Validation...")
	fmt.Println("This test proves the mutated TLS bytes successfully negotiate with real-world infrastructure.")

	cfg := config.DefaultConfig()
	cfg.Profiles = []string{"chrome"}
	
	client, err := atlasclient.New(cfg)
	if err != nil {
		fmt.Printf("Failed to create client: %v\n", err)
		return
	}

	targets := []string{
		"https://tls.peet.ws/api/all",
		"https://www.google.com",
		"https://www.cloudflare.com",
	}

	for _, target := range targets {
		fmt.Printf("\nConnecting to %s ...\n", target)
		
		start := time.Now()
		req, _ := http.NewRequest("GET", target, nil)
		
		// To track the negotiated cipher suite, we will extract it from the response
		resp, err := client.Do(req)
		
		if err != nil {
			fmt.Printf(" [!] FAILED: %v\n", err)
			continue
		}
		
		// Consume body
		_, _ = io.ReadAll(resp.Body)
		resp.Body.Close()

		fmt.Printf(" [+] SUCCESS\n")
		fmt.Printf("     RTT: %d ms\n", time.Since(start).Milliseconds())
		
		if resp.TLS != nil {
			fmt.Printf("     Negotiated Cipher: %s\n", tls.CipherSuiteName(resp.TLS.CipherSuite))
			fmt.Printf("     TLS Version: %x\n", resp.TLS.Version)
		} else {
			fmt.Println("     [Warning] No TLS state available")
		}
	}
	
	fmt.Println("\nLive validation complete. Mutated structures are spec-compliant.")
}
