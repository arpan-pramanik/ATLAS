# ATLAS System Architecture Diagram

This diagram illustrates the structural architecture of the ATLAS system, breaking down the highly-coupled modular components that power the evolutionary TLS camouflage mechanism.

```mermaid
graph TD
    subgraph ATLAS ["ATLAS System"]
        
        subgraph Seed ["Entropy Seeding Layer (High-Entropy Sources)"]
            CF["Cloudflare drand API<br/>(Lava Lamps & Public Randomness)"] -->|"If Online"| Mix{"Cryptographic Mix"}
            FB["Local High-Entropy Fallback<br/>(CPU Jitter + runtime.MemStats)"] -->|"If Offline"| Mix
            CF -.->|"HTTP Fails / Timeout"| FB
            Local["Local OS Entropy<br/>(/dev/urandom + PID + Nanos)"] --> Mix
            Crypto["Standard Crypto RNG<br/>(crypto/rand)"] --> Mix
        end

        subgraph Genome ["Evolutionary Lineage Tracker"]
            Mix --> G["TLS Genome Manager"]
            G --> |"Base utls.ClientHelloSpec<br/>+ Hashes of Last 100 Generations"| ME
        end

        subgraph Compute ["Core Computation & Mutation Engines"]
            ME["Mutation Engine<br/>- Cipher Suite Shuffling & Subsetting<br/>- Extension Order Permutation (SNI pinned)<br/>- ALPN Protocol Reordering<br/>- Dynamic GREASE Injection<br/>- Random Padding Sizes"] 
            MSE["Morphological State Engine<br/>- Computes JA3/JA4 Hashes<br/>- Calculates Uniqueness Index (U_F)<br/>- Calculates Population Entropy (H')<br/>- Generates Surrogate Evasion Metrics"]
            AC{"Adaptive Controller<br/>- Implements Softmax Selection<br/>- Weights: Entropy, Success, Latency, Evasion<br/>- Dynamically Adjusts Mutation Intensity"}
        end

        subgraph Intercept ["Network Intercept & Evaluation"]
            Proxy["MITM Proxy Server<br/>(Port 1080)"]
            Bench["Evaluation Harnesses<br/>(atlas-bench, adaptive-bench, live-validation)"]
        end

        %% Internal Connections
        ME --> |"Evolved Spec"| AC
        MSE --> |"Fitness Metrics (C, U_F, H')"| AC
        AC --> |"Selected Optimal Profile"| Proxy
        AC --> |"Selected Optimal Profile"| Bench
        
        Proxy --> |"Feedback: RTT Latency, Connection Success"| MSE
        Bench --> |"Feedback: RTT Latency, Connection Success"| MSE
    end

    %% External Components
    Client["Internal Client<br/>(Browser/Bot/cURL)"] -->|"HTTP CONNECT"| Proxy
    Proxy -->|"Mutated TLS 1.3 Traffic"| Target["Target DPI / Target TLS Server"]
    AdaptiveAdv["Adaptive Surrogate Classifier<br/>(Simulated Adversary)"] -.->|"Retrains on Observed Traffic"| Bench
    
    classDef primary fill:#2a4d69,stroke:#4b86b4,stroke-width:2px,color:#fff;
    classDef secondary fill:#e7717d,stroke:#c2b9b0,stroke-width:2px,color:#fff;
    classDef external fill:#4b86b4,stroke:#adcbe3,stroke-width:2px,color:#fff;
    
    class AC,ME,MSE primary;
    class CF,Target,Client,AdaptiveAdv external;
    class Proxy,Bench,G secondary;
```
