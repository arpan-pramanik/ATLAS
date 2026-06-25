# ATLAS - System Manual

This manual provides comprehensive instructions for deploying, configuring, and testing the ATLAS adaptive proxy engine.

## Prerequisites
- **OS**: Linux, macOS, or Windows (WSL2 recommended).
- **Go**: Version 1.22 or higher.
- **Docker**: Optional, required only for containerized proxy deployments.
- **Root Certificates**: Installing the MITM proxy certificate requires `mkcert` or manual insertion into your operating system's trust store. Firefox requires importing the certificate manually into its own certificate manager.

## Installation

### Method A: Native Go (Development)
The primary method for running the proxy and benchmarks is natively via Go.
```bash
git clone https://github.com/arpan-pramanik/ATLAS.git
cd ATLAS
go mod download
go build -o atlas-proxy ./atlas/cmd/atlas-proxy
```

### Method B: Docker (Deployment)
If you prefer an isolated environment without installing Go:
```bash
docker-compose up --build -d
```
The proxy will be accessible on `localhost:1080`.

## Configuration
ATLAS uses a JSON configuration file. If no file is provided, a default `config.json` is generated in memory. 

| Field | Type | Description | Safe Defaults |
|-------|------|-------------|---------------|
| `proxy.listen` | String | Address and port to bind the MITM proxy. | `:1080` |
| `proxy.cert_file` | String | Path to the MITM server certificate. | `mitm-cert.pem` |
| `proxy.key_file` | String | Path to the MITM server key. | `mitm-key.pem` |
| `seed.source` | String | Entropy source (`crypto`, `system`). | `crypto` |
| `mutation.*` | Float | Probability (0.0-1.0) of applying specific structural mutations (e.g., `cipher_shuffle`, `alpn_shuffle`). | `0.5` |
| `controller.window_size` | Int | Number of connections to track in the Morphological State Engine. | `100` |
| `controller.weights` | Array | Weights `[w1, w2, w3, w4]` for `[confusion, uniqueness, entropy, reuse_penalty]`. | `[0.3, 0.3, 0.2, 0.2]` |
| `controller.reuse_threshold` | Int | Maximum number of times a TLS profile is used before forced rotation. | `50` |

## Setup (MITM Certificates)
To intercept and mutate TLS traffic, ATLAS must terminate the TLS connection locally.
1. Run the proxy with the `--generate-cert` flag to create local keypairs:
   ```bash
   ./atlas-proxy --listen :1080 --generate-cert
   ```
2. The proxy will generate `mitm-cert.pem` and `mitm-key.pem`.
3. Trust the generated certificate on your machine. For `curl`, you can pass it directly:
   ```bash
   curl -x http://127.0.0.1:1080 --proxy-cacert mitm-cert.pem https://tls.peet.ws/api/all
   ```

## Integration

### 1. Proxy Mode (For Existing Applications)
The proxy daemon (`atlas-proxy`) intercepts system-level traffic. This is ideal when you want to protect existing scripts (Python, Node.js, curl) without changing their source code.

Point your application to use the proxy at `http://127.0.0.1:1080`. ATLAS will terminate the incoming TLS connection and establish a distinct, mutated outbound connection to the destination server.

**Example (Using Python `requests`):**
```python
import requests

proxies = {
    "http": "http://127.0.0.1:1080",
    "https": "http://127.0.0.1:1080"
}

# The request is sent to the proxy. ATLAS intercepts it, mutates the 
# TLS fingerprint, and forwards it to the target server.
response = requests.get("https://tls.peet.ws/api/all", proxies=proxies, verify=False)
print(response.json())
```

### 2. Embeddable Go Client (`atlasclient` - For Custom Go Applications)
If building custom Go applications (such as automated scrapers or bots), you can embed ATLAS directly and use it as a drop-in replacement for the standard `http.Client`.

```go
package main

import (
    "fmt"
    "io"
    "net/http"
    "atlas/atlas/internal/config"
    "atlas/atlas/pkg/atlasclient"
)

func main() {
    // 1. Initialize the ATLAS config
    cfg := config.DefaultConfig()
    cfg.Profiles = []string{"chrome"}

    // 2. Create the ATLAS HTTP client
    client, err := atlasclient.New(cfg)
    if err != nil {
        panic(err)
    }

    // 3. Make requests! The client automatically mutates the TLS fingerprint under the hood.
    req, _ := http.NewRequest("GET", "https://tls.peet.ws/api/all", nil)
    resp, err := client.Do(req)
    if err != nil {
        panic(err)
    }
    defer resp.Body.Close()

    body, _ := io.ReadAll(resp.Body)
    fmt.Println(string(body))
}
```

## Running the Benchmark Suite
The project includes two primary benchmarks that evaluate the entropy metrics in memory without generating network traffic.

1. **`atlas-bench`**: Runs the full Adaptive Controller.
   ```bash
   go run ./atlas/cmd/atlas-bench/main.go -n 1000 -l 20
   ```
2. **`static-bench`**: Runs a baseline evaluation without mutation.
   ```bash
   go run ./atlas/cmd/static-bench/main.go -n 1000
   ```

### Output Interpretation
- **Unique JA3/JA4 Hashes**: The absolute number of distinct fingerprints generated.
- **Global JA3 Entropy ($H'$)**: The normalized Shannon entropy of the fingerprint distribution (1.0 = perfect randomness).
- **Profile Spread Entropy**: Measures how evenly the controller is utilizing its pool of base profiles.
- **Fingerprint Variance Score**: A heuristic estimate measuring the diversity of generated fingerprints to force classifier uncertainty.

## Testing
The `atlas/tests/` directory is currently reserved for the unit testing suite (fingerprint parsing, mutation engine bounds, and benchmark validation). **Note: The testing suite is currently pending implementation and requires contribution.**

## Troubleshooting

1. **Failure Mode**: Immediate connection termination or `bad_certificate` alert.
   - **Reason**: The destination server enforces strict extension ordering and expects the SNI (`server_name`) extension to appear first.
   - **Fix**: The Mutation Engine automatically pins SNI to the 0th index. Ensure your custom profiles do not remove the SNI extension entirely.
2. **Failure Mode**: TLS `decode_error` alerts during handshake.
   - **Reason**: The ClientHello size exceeded MTU boundaries or violated TLS 1.3 chunking rules due to excessive randomized padding.
   - **Fix**: Lower the `padding_mutation` probability in `config.json` to prevent the engine from generating excessively large extension blocks.
3. **Failure Mode**: Proxy fails to initialize entirely.
   - **Reason**: The proxy cannot reach the `drand` entropy API and lacks system entropy.
   - **Fix**: Change `seed.source` in your configuration to `system` to fallback to local `/dev/urandom` and CPU jitter heuristics.

## Reproducing the Ablation Study
To verify the primary claims in the README regarding the balance of entropy and profile spread, you can automatically regenerate the study table:

```bash
# Run the 4-stage ablation simulation
go run ./atlas/cmd/ablation-bench/main.go

# View the mathematical outputs
cat ablation_results.txt
```
The benchmark isolates the Mutation Engine from external network jitter and executes static, multi-profile, pure-random, and full-adaptive conditions iteratively.
