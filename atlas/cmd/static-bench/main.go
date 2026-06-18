package main

import (
	"fmt"
	utls "github.com/refraction-networking/utls"
	"atlas/atlas/internal/fingerprint"
)

func main() {
	fmt.Println("Evaluating Standard uTLS (Static Chrome Preset)")
	seenJA3 := make(map[string]int)

	for i := 0; i < 200; i++ {
		spec, err := utls.UTLSIdToSpec(utls.HelloChrome_120)
		if err != nil {
			panic(err)
		}
		
		fp := fingerprint.Extract(&spec)
		seenJA3[fp.JA3Hash]++
	}

	fmt.Printf("Total Connections: 200\n")
	fmt.Printf("Unique JA3 Hashes: %d\n", len(seenJA3))
	for k, v := range seenJA3 {
		fmt.Printf("- %s: %d times\n", k, v)
	}
}
