#!/usr/bin/env python3
import threading
import queue
import json
import ctypes
import socket
import struct
from flask import Flask, render_template, Response
from bcc import BPF

# 1. Flask & Queue Setup
app = Flask(__name__)
event_queue = queue.Queue()

# 2. Compile eBPF
with open("probe.c", "r") as f:
    bpf_text = f.read()
b = BPF(text=bpf_text)

# Attach Uprobes
b.attach_uprobe(name="crypto", sym="EVP_PKEY_CTX_new_from_name", fn_name="probe_evp_pkey_new")
b.attach_uprobe(name="crypto", sym="EVP_PKEY_CTX_ctrl", fn_name="probe_evp_pkey_ctx_ctrl")
b.attach_uprobe(name="ssl", sym="SSL_set_cipher_list", fn_name="probe_ssl_set_cipher_list")
b.attach_uprobe(name="ssl", sym="SSL_set_ciphersuites", fn_name="probe_ssl_set_cipher_list")

# 3. Payload Structure & Classification (Same as your terminal script)
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
        return "SECURE"
    elif any(legacy in algo_upper for legacy in LEGACY_ALGORITHMS):
        if "RSA" in algo_upper and 0 < bits < 2048:
            return "CRITICAL"
        return "VULNERABLE"
    return "AUDIT"

# 4. The eBPF Callback (Pushes to Queue instead of Terminal)
def handle_event(cpu, data, size):
    evt = ctypes.cast(data, ctypes.POINTER(CryptoEvent)).contents
    
    payload = {
        "pid": evt.pid,
        "process": evt.comm.decode('utf-8', 'replace'),
        "cgroup": evt.cgroup_id,
        "algo": evt.algo_name.decode('utf-8', 'replace') or "Generic Context",
        "bits": evt.bit_length if evt.bit_length > 0 else "N/A",
        "classification": classify_algorithm(evt.algo_name.decode('utf-8', 'replace'), evt.bit_length),
        "type": "memory",
        "network": "N/A"
    }

    if evt.is_network_event == 1:
        payload["type"] = "network"
        payload["network"] = f"{socket.inet_ntoa(struct.pack('<I', evt.daddr))}:{evt.dport}"
    elif evt.is_network_event == 2:
        payload["type"] = "tls"
        payload["algo"] = evt.cipher_suite.decode('utf-8', 'replace')

    # Push to Flask via Queue
    event_queue.put(payload)

b["qfense_events"].open_perf_buffer(handle_event)

# 5. Background Thread for eBPF Polling
def poll_ebpf():
    while True:
        b.perf_buffer_poll()

bpf_thread = threading.Thread(target=poll_ebpf, daemon=True)
bpf_thread.start()

# 6. Flask Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/stream')
def stream():
    def event_stream():
        while True:
            # Block until a new eBPF event arrives
            data = event_queue.get()
            # SSE requires data to be prefixed with 'data: ' and end with double newlines
            yield f"data: {json.dumps(data)}\n\n"
    return Response(event_stream(), mimetype="text/event-stream")

if __name__ == '__main__':
    print("[*] QFense Enterprise Dashboard starting on port 5000...")
    # Run Flask on all interfaces so Codespaces can forward the port
    app.run(host='0.0.0.0', port=5000, threaded=True)