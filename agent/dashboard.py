#!/usr/bin/env python3
from bcc import BPF
import ctypes
import socket
import struct
import json

print("=" * 70)
print("[*] QFense Enterprise Agent: Deep Cryptographic Inspection")
print("=" * 70)

with open("probe.c", "r") as f:
    bpf_text = f.read()

b = BPF(text=bpf_text)

# 1. Attach libcrypto Uprobes (Memory & Bit Length)
b.attach_uprobe(name="crypto", sym="EVP_PKEY_CTX_new_from_name", fn_name="probe_evp_pkey_new")
b.attach_uprobe(name="crypto", sym="EVP_PKEY_CTX_ctrl", fn_name="probe_evp_pkey_ctx_ctrl")

# 2. Attach libssl Uprobes (TLS 1.2 & TLS 1.3 Cipher Suites)
b.attach_uprobe(name="ssl", sym="SSL_set_cipher_list", fn_name="probe_ssl_set_cipher_list")
b.attach_uprobe(name="ssl", sym="SSL_set_ciphersuites", fn_name="probe_ssl_set_cipher_list")

print("[*] Kernel hooks active on libcrypto.so and libssl.so...")

# 3. Aligned Payload Structure
class CryptoEvent(ctypes.Structure):
    _fields_ = [
        ("cgroup_id", ctypes.c_uint64),
        ("pid", ctypes.c_uint32),
        ("bit_length", ctypes.c_uint32),
        ("daddr", ctypes.c_uint32),
        ("dport", ctypes.c_uint16),
        ("is_network_event", ctypes.c_uint8),
        ("_pad", ctypes.c_uint8),
        ("comm", ctypes.c_char * 16),
        ("algo_name", ctypes.c_char * 32),
        ("cipher_suite", ctypes.c_char * 64)
    ]

LEGACY_ALGORITHMS = {"RSA", "EC", "DH", "DSA", "ECDSA", "ECDH", "ED25519", "X25519"}
PQC_ALGORITHMS = {"KYBER", "ML-KEM", "DILITHIUM", "ML-DSA", "FALCON", "SPHINCS+", "SLH-DSA"}

def classify_algorithm(algo, bits):
    algo_upper = algo.upper()
    if any(pqc in algo_upper for pqc in PQC_ALGORITHMS):
        return "[SECURE] Post-Quantum Native (PQC)"
    elif any(legacy in algo_upper for legacy in LEGACY_ALGORITHMS):
        # Dynamically flag weak keys vs standard keys
        if "RSA" in algo_upper and 0 < bits < 2048:
            return "[CRITICAL] Outdated RSA Key Length (< 2048-bit)"
        return "[VULNERABLE] Quantum-Exposed Primitive"
    return "[AUDIT] Custom / Unclassified Algorithm"

def generate_cyclonedx_cbom(pid, cgroup, algo, bits):
    size_block = {"keyLength": bits} if bits > 0 else {}
    cbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "components": [{
            "type": "cryptographic-asset",
            "name": f"process-{pid}-cgroup-{cgroup}",
            "cryptoProperties": {
                "assetType": "algorithm",
                "algorithmProperties": {
                    "algorithmFamily": algo,
                    **size_block
                }
            }
        }]
    }
    print("[*] CycloneDX CBOM Updated:")
    print(json.dumps(cbom, indent=2))

def handle_event(cpu, data, size):
    evt = ctypes.cast(data, ctypes.POINTER(CryptoEvent)).contents
    proc_name = evt.comm.decode('utf-8', 'replace')
    algo_name = evt.algo_name.decode('utf-8', 'replace') or "Generic Context"
    cipher_suite = evt.cipher_suite.decode('utf-8', 'replace')
    classification = classify_algorithm(algo_name, evt.bit_length)

    # Handle the 3 different types of kernel intercepts
    if evt.is_network_event == 1:
        dest_ip = socket.inet_ntoa(struct.pack("<I", evt.daddr))
        print("\n[!] QFENSE NETWORK TELEMETRY: Active Crypto Transmission")
        print(f"    ├─ PID:          {evt.pid} ({proc_name})")
        print(f"    └─ Destination:  {dest_ip}:{evt.dport}")
        print("-" * 70)
        
    elif evt.is_network_event == 2:
        if cipher_suite:
            print("\n[!] QFENSE TLS AUDIT: Cipher Suite Requested")
            print(f"    ├─ PID:          {evt.pid} ({proc_name})")
            print(f"    └─ Suite:        {cipher_suite}")
            print("-" * 70)
            
    else:
        bit_str = f" ({evt.bit_length}-bit)" if evt.bit_length > 0 else ""
        print("\n[*] QFENSE AUDIT: In-Memory Key Creation Detected")
        print(f"    ├─ PID:          {evt.pid} ({proc_name})")
        print(f"    ├─ Container ID: {evt.cgroup_id}")
        print(f"    ├─ Algorithm:    {algo_name}{bit_str}")
        print(f"    └─ Assessment:   {classification}")
        print("-" * 70)
        generate_cyclonedx_cbom(evt.pid, evt.cgroup_id, algo_name, evt.bit_length)

b["qfense_events"].open_perf_buffer(handle_event)
try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("\n[*] Terminating QFense Agent.")