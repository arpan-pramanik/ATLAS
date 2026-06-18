package main

import (
	"fmt"
	"time"

	"atlas/atlas/internal/benchmark"
	"atlas/atlas/internal/config"

	"github.com/jessevdk/go-flags"
	"github.com/sirupsen/logrus"
)

type Options struct {
	Iterations int    `short:"n" long:"iterations" description:"Number of connections to simulate" default:"1000"`
	Latency    int    `short:"l" long:"latency" description:"Simulated base network latency (ms)" default:"20"`
	ConfigFile string `short:"c" long:"config" description:"Path to config file (optional)"`
}

func main() {
	var opts Options
	parser := flags.NewParser(&opts, flags.Default)
	if _, err := parser.Parse(); err != nil {
		return // flags prints the error
	}

	cfg, err := config.LoadConfig(opts.ConfigFile)
	if err != nil {
		logrus.Fatalf("Failed to load config: %v", err)
	}

	fmt.Printf("Starting ATLAS Benchmark Engine...\n")
	fmt.Printf("Simulating %d connections with base network latency %dms\n", opts.Iterations, opts.Latency)
	fmt.Printf("Seed Source: %s\n\n", cfg.Seed.Source)

	start := time.Now()
	res, err := benchmark.RunBenchmark(opts.Iterations, time.Duration(opts.Latency)*time.Millisecond, cfg)
	if err != nil {
		logrus.Fatalf("Benchmark failed: %v", err)
	}
	elapsed := time.Since(start)

	fmt.Println(benchmark.PrintResults(res))
	fmt.Printf("\nBenchmark completed in %v\n", elapsed)
}
