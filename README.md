# QFense eBPF Agent 🛡️⚡
> **Runtime Cryptographic Observability & Post-Quantum Readiness for Kubernetes**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![eBPF: CO-RE](https://img.shields.io/badge/eBPF-CO--RE%20libbpf-orange.svg)](https://ebpf.io/)
[![Standard: CycloneDX 1.7](https://img.shields.io/badge/CBOM-CycloneDX%201.7-green.svg)](https://cyclonedx.org/)

QFense is an open-source, Kubernetes-native eBPF agent designed to solve the "Harvest Now, Decrypt Later" threat. Static code scanners cannot see ephemeral keys or containerized microservices. QFense intercepts cryptographic execution in live memory, attributes it to specific containers, and generates CycloneDX 1.7 Cryptographic Bills of Materials (CBOMs).

## 🏛️ Architecture

1. **Kernel Space (eBPF):** Uprobes hook OpenSSL (`libcrypto.so.3`) to capture `Context Creation`, `Keygen Initiation`, and `Keygen Success`. Built using CO-RE (Compile Once – Run Everywhere).
2. **Agent (C / libbpf):** A 58MB C-based loader reads from the BPF Ring Buffer and outputs structured JSON to `stdout`.
3. **Kubernetes (DaemonSet):** The C agent runs as a DaemonSet on every node.
4. **Bridge (Python):** Tails the Kubernetes logs, parses the JSON, and resolves host PIDs to exact container IDs via `/proc/<pid>/cgroup`.
5. **Control Plane (Flask):** Receives JSON events, applies an **Evidence-Aware Risk Engine**, saves to SQLite, and streams to the web UI via Server-Sent Events (SSE).

## ✨ Verified vs. Roadmap (Honest Assessment)

| Capability | Status |
|---|---|
| eBPF Uprobes on OpenSSL 3 (`EVP_PKEY_*`) | ✅ Verified |
| Context vs. Keygen Semantic Distinction | ✅ Verified |
| CO-RE libbpf Loader (No runtime compilation) | ✅ Verified |
| Kubernetes DaemonSet Deployment | ✅ Verified |
| Container Attribution (Docker/containerd via cgroups) | ✅ Verified |
| Evidence-Aware Risk Engine (HIGH/MEDIUM/INFO) | ✅ Verified |
| CycloneDX 1.7 CBOM Export | ✅ Verified |
| Multi-library support (GnuTLS, BoringSSL) | ⏳ Roadmap |
| Centralized Multi-Node Control Plane | ⏳ Roadmap |

## 📊 Preliminary Benchmarking
We benchmarked the eBPF uprobe overhead by measuring the time to generate 100 RSA-2048 keys (5-run median).
*   **Baseline (No Agent):** `25.9s`
*   **Active (With Agent):** `25.8s`
*   **Overhead:** `< 1%` (Within standard OS caching noise).
*Note: This benchmark covers host-level RSA keygen. High-throughput TLS benchmarking is ongoing.*

## 🚀 Quickstart

### Prerequisites
*   Linux kernel **5.15+** with BTF support.
*   Kubernetes cluster (K3s recommended for local testing).
*   `kubectl` configured with cluster access.

### 1. Deploy the Agent (Kubernetes)
```bash
sudo kubectl apply -f daemonset.yaml
sudo kubectl get pods -n kube-system -l app=qfense-agent
