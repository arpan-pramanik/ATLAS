# ATLAS - Adaptive Transport Layer Anonymization System

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.20836805.svg)](https://doi.org/10.5281/zenodo.20836805)

An adaptive anti-fingerprinting network defense that dynamically camouflages TLS handshakes using entropy-aware, profile-rotating mutation policies, evaluated against modern JA3/JA4-style fingerprinting classifiers. 

This is explicitly not "TLS spoofing" in the simplistic sense of faking a single browser. ATLAS uses a continuous measurement-driven control loop to balance fingerprint diversity with connection stability.

## Threat Model and Capabilities

### Adversary
We assume a passive on-path observer (ISP, enterprise middlebox, or network-level detection system) that can log full TLS handshakes but cannot modify traffic in transit. 
The adversary is capable of:
- Computing JA3, JA3S, JA4, JARM, and similar fingerprints from intercepted handshakes.
- Training ML classifiers (e.g., XGBoost, Random Forest) on fingerprint features to classify client software types, automation indicators, or specific applications.
- Maintaining historical logs to exploit the stability of fingerprints over time.

### Defender Constraints
ATLAS operates as a client-side middleware proxy that intercepts outgoing TLS connections.
- It can modify the `ClientHello` fields (cipher suites, extensions and their order, ALPN, padding, session ticket behavior, supported groups, signature algorithms).
- It must keep the handshake spec-compliant and functional.
- It cannot break TLS security assumptions (no downgrade to known-weak ciphers, no invalid certificate checks).

## Related Work and Architecture Gap

Current evasion and mimicry tooling focuses on static mimicry or pure randomization, lacking the feedback necessary to evade adaptive classifiers safely.

| System | Approach | Limitations vs ATLAS |
|--------|----------|----------------------|
| **uTLS** | Static browser impersonation and randomized fingerprints. | Parrots existing fingerprints but lacks an explicit measurement or control loop. Does not compute entropy or tune policies dynamically. |
| **Chrome Extension Permutation** | Permutes the list of extensions for each connection deterministically. | Targets protocol robustness, not privacy. Does not monitor population uniqueness or tune intensity based on network risk. |
| **ATLAS (This Work)** | Continuous, metric-driven mutation using an Adaptive Controller. | Actively measures fingerprint uniqueness ($U_F$) and entropy ($H'(X)$), rotating profiles and adjusting mutation weights based on mathematical targets. |

## Implementation Rationale

ATLAS is implemented in **Go** leveraging a customized integration with **uTLS**, rather than the Python `mitmproxy` stack often suggested in literature. This decision was driven by engineering constraints:
1. **Performance**: Go provides significantly lower memory overhead and predictable latency, which is critical when measuring the RTT impact of mutations.
2. **Native TLS Manipulation**: uTLS provides native, low-level structs (`utls.ClientHelloSpec`) that are far safer and more performant to mutate in real-time than Python-level packet interception.
3. **Deployment**: A single statically compiled binary allows the proxy to be deployed consistently without a complex Python environment.

## Formal Metrics

The Adaptive Controller tracks the following metrics over a sliding window of connections to calculate a fitness score $S(p)$ for profile $p$:

1. **Uniqueness Index ($U_F$)**: For each fingerprint type $F$ over a window size $N$, we calculate the maximum frequency of any hash $c$:
   $$U_F = 1 - \frac{\max_c \text{count}_F(c)}{N}$$
   A high $U_F$ indicates no single hash dominates the traffic.

2. **Feature-Space Entropy ($H'(X)$)**: We compute the empirical Shannon entropy for categorical features (cipher suites, extensions) and normalize it by the maximum possible entropy:
   $$H(X) = - \sum_i p_i \log_2 p_i$$
   $$H'(X) = \frac{H(X)}{\log_2 |\mathcal{X}|}$$

3. **Fingerprint Variance Score ($C$)**: An estimated heuristic measuring the diversity of generated fingerprints to force classifier uncertainty. 

The fitness score used for Softmax selection is:
$$S(p) = w_1 \cdot C + w_2 \cdot U_F + w_3 \cdot H'(X) - w_4 \cdot \text{reuse}_p$$

## Ablation Study Results

To evaluate the contribution of the Adaptive Controller, we simulated 500 connections across four configurations using `atlas-bench`. 

| Condition | Unique JA3 Hashes | Global JA3 Entropy ($H'$) | Profile Spread Entropy | Variance Score |
|-----------|-------------------|---------------------------|------------------------|----------------|
| **Baseline (Static Mimic)** | 1 | 0.0000 | 0.0000 | 0.0347 |
| **Multi-Profile (No Mutation)** | 3 | 0.9998 | 0.9998 | 0.0928 |
| **Static-Random (Pure Mutation)** | 500 | 1.0000 | 0.0000 | 1.0000 |
| **Full-Adaptive (ATLAS Default)** | 388 | 0.9625 | 0.9985 | 1.0000 |

**Conclusion:** Pure randomization (Static-Random) maximizes entropy but uses no profile variance, which is easily classified as anomalous. The Full-Adaptive ATLAS configuration successfully balances profile-spread plausibility ($0.9985$ spread) while matching the variance of pure randomization ($1.0000$), ensuring the generated fingerprints are mathematically diverse while remaining structurally plausible.

## How to Use

- **Documentation:**
  - [System Manual & Implementation Guide](./documents/Manual.md)
  - [Architecture Documentation](./documents/diagram-architecture.md)
  - [Legal Notice & Ethics Policy](./documents/LEGAL_AND_ETHICS_POLICY.md).

### 1. Standalone MITM Proxy
Route external traffic (e.g., from `curl` or browsers) through the ATLAS engine:
```bash
# Build and start the proxy
go build -o atlas-proxy ./atlas/cmd/atlas-proxy
./atlas-proxy --listen :1080 --generate-cert

# Test via curl
curl -x http://127.0.0.1:1080 --proxy-cacert mitm-cert.pem https://tls.peet.ws/api/all
```

### 2. Embeddable Go Client
Embed ATLAS directly into the standard `http.Client` for custom Go tooling:
```go
import "atlas/atlas/pkg/atlasclient"

client, _ := atlasclient.New(nil)
resp, _ := client.Get("https://tls.peet.ws/api/all")
```

### 3. Docker Deployment
```bash
docker-compose up --build -d
```

## Engineering Log

- **Issue:** Randomizing all extension orderings blindly.
  **Result:** Resulted in immediate connection termination from certain strict servers that expect `server_name` (SNI) to be the first extension.
  **Fix:** Constrained the Mutation Engine to always pin SNI to the first position before shuffling the remaining slice.
- **Issue:** Generating random padding lengths.
  **Result:** Encountered `decode_error` alerts when the total ClientHello size exceeded typical MTU boundaries or violated TLS 1.3 chunking rules.
  **Fix:** Applied an upper bound to the padding extension generator.
- **Issue:** Network failures when reaching the `drand` API for entropy seeding.
  **Result:** The proxy failed to initialize if offline.
  **Fix:** Implemented a local fallback heuristic (`generateLocalHighEntropySeed`) utilizing `runtime.ReadMemStats` and CPU jitter loops to guarantee continuous operation.

## Experimental Setup and Reproducibility

Benchmarks are generated using `atlas/cmd/ablation-bench`. Connections are simulated entirely in-memory using `utls.ClientHelloSpec` serialization to isolate the mathematical impact of the Mutation Engine from external network jitter. The base latency was statically configured to $20\text{ms}$. Future live-traffic studies will use `tshark` PCAP captures to validate against external infrastructure.

## Limitations

1. **Synthetic Benchmarks**: The current evaluations are simulated within `atlas-bench` to validate the statistical properties of the engine. Live-network evaluations against a physical proxy target are planned.
2. **Surrogate Variance Metric**: The `Variance Score` used in the Adaptive Controller is a mathematical heuristic based on fingerprint diversity. It has not been directly validated against a surrogate XGBoost/CatBoost classifier because we ran out of time during the initial research sprint to train the surrogate model specified in our methodology. As such, the metric assumes that higher mathematical variance correlates with increased evasion capability, which must be empirically proven in future work.

## References

1. JA3 Fingerprints Fade as Browsers Embrace TLS Extension Randomization.
2. refraction-networking/utls Go Packages.
3. Examining Chrome's TLS ClientHello Permutation.
4. TLS Fingerprinting: Advanced Guide for Security Engineers 2025.
5. Effective TLS Fingerprinting Beyond JA3.
6. When Handshakes Tell the Truth: Detecting Web Bad Bots via TLS Fingerprints.
7. What is JA3 Fingerprinting?
8. When Handshakes Tell the Truth: Detecting Web Bad Bots via TLS... (arXiv:2602.09606).
9. TLS Fingerprint for Malicious Traffic Detection with Attributed Graph.
10. TLS fingerprint for encrypted malicious traffic detection.
11. The use of TLS in Censorship Circumvention (NDSS 2019).
12. Traffic Flow Analysis of Tor Pluggable Transports.
13. Tor design proposals.
14. Adaptive Webpage Fingerprinting from TLS Traces.


