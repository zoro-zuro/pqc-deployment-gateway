# FinTech Quantum-Shield: Post-Quantum Code Signer & Zero-Trust Deployment Gateway

[![Standard](https://img.shields.io/badge/Standard-NIST%20FIPS%20204%20(ML--DSA--65)-blue.svg)](https://csrc.nist.gov/pubs/fips/204/final)
[![Security](https://img.shields.io/badge/Cryptography-Lattice--Based%20(M--LWE)-green.svg)](https://csrc.nist.gov)
[![Status](https://img.shields.io/badge/Deployment-Cloudflare%20Edge%20Gate-orange.svg)](https://trycloudflare.com)

A zero-trust cryptographic deployment perimeter powered by **NIST FIPS 204 ML-DSA-65 (Module-Lattice Digital Signature Algorithm)**. It prevents CI/CD supply-chain poisoning attacks (SolarWinds style) and ensures quantum-resistant software distribution.

---

## 🎯 Key Capabilities
1. **NIST FIPS 204 Standard:** Uses official post-quantum lattice cryptography (ML-DSA-65) resilient against Shor's Algorithm on quantum computers.
2. **Zero-Trust Host Separation:** The cloud deployment gate holds **only the public key (1,952 bytes)**. The private signing key (4,032 bytes) never leaves the developer's secure environment.
3. **CI/CD Supply Chain Defense:** Detects build-time malicious dependency injections and drops tampered payloads with HTTP 403 Forbidden.
4. **Live Enterprise Dashboard:** Real-time DevSecOps deployment tracking and audit log stream over Cloudflare HTTPS edge tunnels.

---

## 📋 System Prerequisites
- **Python:** 3.10 or higher
- **OS:** Windows 10/11, Linux, or macOS
- **Dependencies:** `cryptography >= 50.0.0`, `typer >= 0.12.0`, `rich >= 13.0.0`
- **Cloudflare Tunnel (Optional for Global Edge):** Standalone `cloudflared` executable included in the repository.

---

## 🚀 Quick Setup & Installation

Clone the repository and install dependencies in editable mode:

```bash
git clone https://github.com/YOUR_USERNAME/pqc-deployment-gateway.git
cd pqc-deployment-gateway

# Install dependencies
pip install -r requirements.txt
pip install -e .
```

Verify installation:
```bash
python -m pqc_cli.cli --help
```

---

## 🧪 Demonstration Guide (Step-by-Step)

The demonstration is divided into two phases: **Core CLI Foundation** and **Live Edge Gateway Defense**.

### Phase 1: Core Cryptographic Engine (CLI)

1. **Generate Post-Quantum Keypair:**
   ```bash
   python -m pqc_cli.cli keygen
   ```
   *Generates `keys/public.key` (1,952 bytes) and `keys/private.key` (4,032 bytes).*

2. **Sign Software Artifact:**
   ```bash
   python -m pqc_cli.cli sign demo/app.bin
   ```
   *Creates mathematical lattice signature bundle `demo/app.bin.sig` (3,309 bytes).*

3. **Verify Clean Artifact (Expected: ALLOW):**
   ```bash
   python -m pqc_cli.cli verify demo/app.bin
   ```

4. **Verify Tampered Artifact (Expected: BLOCK):**
   ```bash
   python -m pqc_cli.cli verify demo/app_tampered.bin --signature demo/app.bin.sig
   ```

---

### Phase 2: Live Cloudflare Edge Network Deployment

Simulates a modern enterprise banking pipeline where code is pushed across the internet to a production cluster.

#### 1. Start Background Services

- **Terminal 1: Start Production Gateway Server**
  ```bash
  python -m pqc_cli.cli serve --port 8080 --public-key keys/public.key
  ```

- **Terminal 2: Start Cloudflare Live Tunnel (Global Internet URL)**
  ```bash
  .\cloudflared.exe tunnel --url http://127.0.0.1:8080
  ```
  *Copy the generated HTTPS URL: `https://<random-id>.trycloudflare.com`*

- **Browser:** Open the Cloudflare URL to view the real-time **Enterprise Deployment Dashboard**.

---

#### 2. Run Deployment Scenarios (Terminal 3)

- **Step A: Legitimate Build Release**
  ```bash
  # Compile clean payment bundle
  python demo/build_pipeline.py

  # Sign bundle with Post-Quantum Private Key
  python -m pqc_cli.cli sign demo/payment_bundle.py

  # Deploy to Cloud Gateway
  python -m pqc_cli.cli deploy demo/payment_bundle.py --host <CLOUDFLARE_URL> --private-key keys/private.key
  ```
  *Result: Terminal shows `APPROVED`. Browser dashboard updates to `SECURED BY ML-DSA-65` (Green).*

- **Step B: Supply-Chain Dependency Poisoning (Legacy Attack)**
  ```bash
  # Simulate CI/CD pulling compromised upstream dependency
  python demo/build_pipeline.py --poison

  # Deploy using legacy unverified pipeline
  python -m pqc_cli.cli deploy demo/payment_bundle.py --host <CLOUDFLARE_URL> --legacy
  ```
  *Result: Terminal warns of bypass. Browser dashboard turns **RED** (`COMPROMISED ARTIFACT IN PRODUCTION`).*

- **Step C: Reset to Baseline**
  ```bash
  python -m pqc_cli.cli reset-server --host <CLOUDFLARE_URL>
  ```

- **Step D: Post-Quantum Defense in Action**
  ```bash
  # Attempt to deploy the poisoned build through the PQC Gateway
  python -m pqc_cli.cli deploy demo/payment_bundle.py --host <CLOUDFLARE_URL> --private-key keys/private.key --signature demo/payment_bundle.py.sig
  ```
  *Result: **HTTP 403 FORBIDDEN — REJECTED**. Cloudflare drops payload at perimeter. Live cluster remains safe.*

---

## 📁 Repository Structure
```
├── demo/
│   ├── app.bin                  # Clean baseline binary
│   ├── app_tampered.bin         # Manually altered binary
│   ├── build_pipeline.py        # CI/CD simulator (Clean vs Poisoned dependency)
│   └── payment_processor.py     # Production banking module source
├── keys/                        # Post-Quantum cryptographic keys (Auto-generated)
├── pqc_cli/                     # Core system modules
│   ├── cli.py                   # Typer CLI application interface
│   ├── client.py                # Deployment client & network dispatch
│   ├── crypto_backend.py        # NIST FIPS 204 ML-DSA engine abstraction
│   ├── key_manager.py           # Keystore operations
│   ├── server.py                # Gateway server & FinTech DevSecOps dashboard
│   ├── signer.py                # Signature generation engine
│   ├── utils.py                 # SHA-256 hash & formatting utilities
│   └── verifier.py              # Lattice verification engine
├── cloudflared.exe              # Standalone Cloudflare Tunnel client
├── IMPACT.md                    # Academic & real-world business impact analysis
├── pyproject.toml               # Package configuration
└── requirements.txt             # Project dependencies
```

---

## 📜 Academic Standards & Citations
- **NIST FIPS 204:** *Module-Lattice-Based Digital Signature Standard (ML-DSA)*, August 2024.
- **Threat Vector Reference:** Supply-chain compromise model based on MITRE ATT&CK T1195 (Supply Chain Compromise) and SolarWinds (SUNBURST) architectural analysis.
