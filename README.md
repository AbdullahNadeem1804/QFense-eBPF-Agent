# QFense eBPF Agent 🛡️

> **Dynamic Live-Memory Cryptographic Discovery & Post-Quantum (PQC) Telemetry Engine**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![eBPF: Linux Kernel](https://img.shields.io/badge/eBPF-Kernel%206.x-orange.svg)](https://ebpf.io/)
[![Standard: CycloneDX 1.7](https://img.shields.io/badge/CBOM-CycloneDX%201.7-green.svg)](https://cyclonedx.org/)

QFense eBPF Agent is a cryptographic observability tool designed to discover cryptographic activity from live Linux workloads. It uses **eBPF user-space probes (Uprobes)** and **kernel probes (Kprobes)** to observe selected cryptographic and network events associated with `libcrypto.so` and `libssl.so`.

The collected telemetry is classified according to its post-quantum relevance and can be represented as a dynamic **Cryptographic Bill of Materials (CBOM)** using the **CycloneDX 1.7** format. A live web dashboard provides visibility into detected cryptographic activity and associated workload metadata.

---

## Architecture Overview

```text
                ┌────────────────────────────────────────────────────────────┐
                │                     User-Space Workloads                   │
                │        OpenSSL • Python • Nginx • Microservices            │
                └───────────────────────┬───────────────────┬────────────────┘
                                        │                   │
                                        ▼                   ▼
                              Uprobe: libcrypto.so   Uprobe: libssl.so
                                        │                   │
                                        │                   │
                                        └─────────┬─────────┘
                                                  ▼
                ┌────────────────────────────────────────────────────────────┐
                │                       Linux Kernel                         │
                │                                                            │
                │   ┌─────────────────────────┐   ┌────────────────────────┐ │
                │   │ BPF_HASH Deduplication  │   │ Kprobe: tcp_connect    │ │
                │   └────────────┬────────────┘   └────────────┬───────────┘ │
                │                │                             │             │
                │                └──────────────┬──────────────┘             │
                │                               ▼                            │
                │              BPF Perf/Ring Buffer → User Space             │
                └───────────────────────────────┬────────────────────────────┘
                                                │
                                                ▼
                ┌────────────────────────────────────────────────────────────┐
                │                  QFense Control & UI Layer                 │
                │                                                            │
                │  • Cryptographic classification                            │
                │  • PQC exposure analysis                                   │
                │  • Dynamic CycloneDX 1.7 CBOM generation                   │
                │  • Process and container attribution                       │
                │  • Live Server-Sent Events (SSE) dashboard                 │
                └────────────────────────────────────────────────────────────┘
```

### Telemetry Flow

1. QFense attaches eBPF probes to supported OpenSSL-related functions and selected kernel events.
2. Relevant events are captured in kernel space.
3. Kernel-side deduplication reduces repeated telemetry.
4. Events are transferred to user space through the BPF event buffer.
5. QFense enriches events with process and workload metadata.
6. Cryptographic algorithms are classified according to their post-quantum exposure.
7. The resulting telemetry can be exposed through the live dashboard and CBOM output.

---

## Key Features

### Live Cryptographic Observability

Observes selected cryptographic operations from live application execution instead of relying exclusively on static configuration or filesystem inspection.

### eBPF-Based Instrumentation

Uses Linux eBPF **Uprobes** for user-space instrumentation and **Kprobes** for kernel-level network telemetry.

### Kernel-Side Deduplication

Uses an eBPF hash map to reduce duplicate events and help prevent telemetry floods during high-frequency workloads.

### Post-Quantum Risk Classification

Groups observed cryptographic algorithms according to their post-quantum relevance, including examples such as:

- **PQC / post-quantum algorithms:** ML-KEM, ML-DSA
- **Classical algorithms with quantum exposure:** RSA, ECDSA, X25519

> Classification is intended for cryptographic inventory and observability. It is not a replacement for a complete cryptographic risk assessment.

### Dynamic CBOM Generation

Produces CycloneDX 1.7-compatible CBOM data containing cryptographic asset information such as:

- Algorithm family
- Key length, where available
- Process attribution
- Container/workload metadata, where available

### Container-Aware Telemetry

Designed for containerized Linux environments, with workload attribution using kernel-level metadata such as `cgroup_id`.

### Live Enterprise Web Dashboard

Provides a browser-based interface for monitoring detected telemetry, with live event delivery through **Server-Sent Events (SSE)**.

---

## 📸 Live Memory Interception

QFense is designed to observe cryptographic activity at runtime, providing visibility into execution paths that may not be obvious from static configuration alone.

![QFense Intercepting Python Runtime](assets/hero-intercept.png)

---

## 📦 Dynamic CycloneDX CBOM

Detected cryptographic activity can be represented as a CycloneDX 1.7 Cryptographic Bill of Materials.

![CycloneDX CBOM Output](assets/cbom-output.png)

---

## 🚀 Quickstart

### Prerequisites

A Linux host with:

- Linux kernel **5.15+**
- BPF/BTF support
- Docker Engine
- Kernel tracing support
- Permissions required for privileged eBPF execution

The Docker deployment also expects access to the relevant host kernel and tracing paths.

### 1. Clone the Repository

```bash
git clone https://github.com/AbdullahNadeem1804/QFense-eBPF-Agent.git
cd QFense-eBPF-Agent
```

### 2. Build the Docker Image

```bash
sudo docker build -t qfense-agent:v1 .
```

### 3. Launch the QFense Agent

```bash
sudo docker run -d \
  --name qfense-node \
  --privileged \
  -v /sys/kernel/tracing:/sys/kernel/tracing:rw \
  -v /lib/modules:/lib/modules:ro \
  -v /usr/src:/usr/src:ro \
  -p 5000:5000 \
  qfense-agent:v1
```

### 4. Open the Dashboard

Open the following address in a browser:

```text
http://localhost:5000
```

### 5. Trigger the Demonstration Workload

Run the included demonstration script inside the container:

```bash
sudo docker exec -it qfense-node python3 demo_trigger.py
```

The demonstration is intended to generate representative legacy and post-quantum-related telemetry for the dashboard.

---

## 🧪 Manual Workload Testing

If you want to generate additional OpenSSL activity from a Linux host, examples include:

### RSA Key Generation

```bash
openssl genpkey \
  -algorithm RSA \
  -pkeyopt rsa_keygen_bits:2048
```

### TLS Client Connection

```bash
openssl s_client \
  -connect 1.1.1.1:443 \
  -quiet
```

> The exact events observed depend on the OpenSSL version, linked libraries, probe targets, permissions, and the implementation currently deployed in QFense.

---

## 📋 Sample Dynamic CBOM

A simplified example of the generated CBOM structure:

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.7",
  "components": [
    {
      "type": "cryptographic-asset",
      "name": "process-28329-cgroup-8310",
      "cryptoProperties": {
        "assetType": "algorithm",
        "algorithmProperties": {
          "algorithmFamily": "RSA",
          "keyLength": 2048
        }
      }
    }
  ]
}
```

The exact fields and values depend on the telemetry available at runtime.

---

## 🐳 Docker Deployment Notes

QFense requires elevated privileges because eBPF instrumentation interacts with the host kernel and tracing infrastructure.

The example container configuration mounts:

| Host Path | Purpose |
|---|---|
| `/sys/kernel/tracing` | Kernel tracing interface |
| `/lib/modules` | Host kernel modules |
| `/usr/src` | Kernel headers/source required by some eBPF build paths |

The container is launched with `--privileged` in the current deployment model.

### Security Consideration

Running an eBPF monitoring container with `--privileged` provides broad access to host resources. This configuration is appropriate for controlled research, testing, and lab environments, but should be reviewed and hardened before production deployment.

---

## 🗺️ Roadmap

- [x] eBPF Uprobes on OpenSSL 3.0 (`libcrypto.so`)
- [x] Kernel-space deduplication using `BPF_HASH`
- [x] CycloneDX 1.7 CBOM generation
- [x] Containerized web dashboard with Flask/SSE
- [ ] CO-RE (Compile Once – Run Everywhere) migration using `libbpf`
- [ ] Kubernetes DaemonSet deployment and Helm chart
- [ ] Envoy memory-hook support
- [ ] GnuTLS memory-hook support

---

## 📁 Project Structure

```text
QFense-eBPF-Agent/
├── assets/
│   ├── hero-intercept.png
│   └── cbom-output.png
├── Dockerfile
├── dashboard.py
├── demo_trigger.py
├── ...
└── README.md
```

> The structure above is illustrative. Keep it synchronized with the actual repository layout as the project evolves.

---

## ⚠️ Current Limitations

QFense currently depends on Linux kernel and OpenSSL implementation details. Probe compatibility can vary between distributions, kernel versions, OpenSSL builds, and library layouts.

In particular:

- eBPF attachment points may differ across OpenSSL versions.
- Not every cryptographic operation exposes all desired metadata.
- Container attribution depends on the available kernel/runtime metadata.
- PQC classification describes algorithm-level exposure and does not by itself establish application-wide cryptographic security.
- The current Docker deployment uses privileged execution.
- CO-RE portability is part of the roadmap rather than the current deployment model.

---

## 🤝 Contributing

Contributions, experiments, bug reports, and improvements are welcome.

Before submitting a pull request:

1. Test changes on a supported Linux environment.
2. Document any kernel or OpenSSL compatibility requirements.
3. Avoid committing generated telemetry containing sensitive information.
4. Update the documentation when behavior or deployment requirements change.

---

## 📄 License

This project is licensed under the MIT License. See the [`LICENSE`](LICENSE) file for details.
