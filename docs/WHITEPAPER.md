# QFense: Runtime Cryptographic Observability for Cloud-Native Infrastructure

**Author:** Abdullah Nadeem
**Project:** QFense eBPF Agent
**Status:** Open-source research prototype

## 1. Executive Summary
As organizations prepare for Post-Quantum Cryptography (PQC) migration, they face a critical blind spot: they do not know where their legacy cryptography is actively running. Static scanners cannot observe ephemeral keys, dynamic memory, or containerized microservices. QFense is a Kubernetes-native eBPF agent that solves this by intercepting OpenSSL execution in live memory and generating CycloneDX 1.7 CBOMs.

## 2. The Threat Model: Harvest Now, Decrypt Later (HNDL)
Adversaries are currently recording encrypted network traffic with the expectation that future quantum computers will decrypt it. To mitigate this, organizations must identify and migrate all instances of quantum-vulnerable algorithms (RSA, ECC) to Post-Quantum standards (ML-KEM, ML-DSA).

## 3. Architecture & Technical Implementation
QFense leverages **eBPF (Extended Berkeley Packet Filter)** and **CO-RE (Compile Once – Run Everywhere)** to provide deep observability without the overhead of traditional agents.

*   **Kernel-Space Interception:** The agent uses eBPF Uprobes to hook into `libcrypto.so` (`EVP_PKEY_CTX_new_from_name` and `EVP_PKEY_generate`). It captures context creation, keygen initiation, and keygen success.
*   **Container Attribution:** It resolves the host Process ID (PID) to the specific container ID via `/proc` and cgroups, providing microservice-level context.
*   **Semantic Accuracy:** The engine distinguishes between an algorithm context request and a completed key generation, eliminating alert fatigue.
*   **Control Plane & Dashboard:** A Flask-based log bridge ingests kernel events, applies an Evidence-Aware Risk Engine, and streams them to a real-time Tailwind CSS dashboard.
*   **Compliance:** Automatically generates CycloneDX 1.7 Cryptographic Bills of Materials (CBOMs).

## 4. Benchmarking & Performance
A critical requirement for enterprise adoption is ensuring the agent does not degrade system performance. We benchmarked the eBPF uprobes by measuring the time required to generate 100 RSA-2048 keys (5-run median).

*   **Baseline (No Agent):** `25.9s`
*   **Active (With eBPF Agent):** `25.8s`
*   **Overhead:** `< 1%` (within standard OS caching noise).

## 5. Current Limitations & Future Work
*   **Container Library Isolation:** The agent currently instruments the host's `libcrypto.so.3`. Instrumenting isolated container libraries requires dynamic library discovery (`openat` syscall tracking), which is planned for the next iteration.
*   **Library Support:** Only OpenSSL 3 is currently supported; GnuTLS and BoringSSL are planned.

## 6. Conclusion
QFense demonstrates that runtime cryptographic observability is achievable with near-zero overhead. By providing real-time evidence of cryptographic operations, it empowers security teams to prioritize their PQC migration efforts based on actual runtime data, not just static assumptions.
