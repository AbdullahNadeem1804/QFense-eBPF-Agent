#!/usr/bin/env python3
from bcc import BPF
import ctypes
import re
import argparse

parser = argparse.ArgumentParser(description="QFense Semantic Discovery Engine")
parser.add_argument("--pid", type=int, help="Attach to a specific PID", default=-1)
parser.add_argument("--lib", type=str, help="Library to attach to (name or path)", default="crypto")
args = parser.parse_args()

print("=" * 60)
print(f"[*] QFense Enterprise Agent: Semantic Discovery Engine")
print(f"[*] Target Library: {args.lib}")
if args.pid != -1:
    print(f"[*] Mode: PID Target ({args.pid})")
print("=" * 60)

with open("probe.c", "r") as f:
    bpf_text = f.read()

b = BPF(text=bpf_text)

# Use the specific library path provided
print("[*] Attaching Context Probe...")
b.attach_uprobe(name=args.lib, sym="EVP_PKEY_CTX_new_from_name", fn_name="probe_evp_context", pid=args.pid)

print("[*] Attaching Keygen Entry Probe...")
b.attach_uprobe(name=args.lib, sym="EVP_PKEY_generate", fn_name="probe_evp_keygen_entry", pid=args.pid)

print("[*] Attaching Keygen Return Probe...")
b.attach_uretprobe(name=args.lib, sym="EVP_PKEY_generate", fn_name="probe_evp_keygen_return", pid=args.pid)

class CryptoEvent(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("cgroup_id", ctypes.c_uint64),
        ("pid", ctypes.c_uint32),
        ("event_type", ctypes.c_uint8),
        ("comm", ctypes.c_char * 16),
        ("algo_name", ctypes.c_char * 32)
    ]

def get_container_id(pid):
    """Reads /proc to resolve the Docker/containerd container ID."""
    try:
        with open(f"/proc/{pid}/cgroup", "r") as f:
            cgroup_path = f.read()
        
        # Look for the 64-character hex string (Docker or containerd)
        match = re.search(r'(?:docker|containerd)-([a-f0-9]{64})', cgroup_path)
        if match:
            return match.group(1)[:12] # Return the short 12-char ID
    except FileNotFoundError:
        pass
    return "Host Process"

def handle_event(cpu, data, size):
    evt = ctypes.cast(data, ctypes.POINTER(CryptoEvent)).contents
    proc_name = evt.comm.decode('utf-8', 'replace')
    algo_name = evt.algo_name.decode('utf-8', 'replace') or "Unknown"
    
    # Resolve the container ID
    container_id = get_container_id(evt.pid)
    
    if evt.event_type == 0:
        action = "[CONTEXT] Algorithm Requested"
        color = "\033[93m"
    elif evt.event_type == 1:
        action = "[ACTION]  Key Generation Initiated"
        color = "\033[96m"
    elif evt.event_type == 2:
        action = "[SUCCESS] Key Generated Successfully"
        color = "\033[92m"
    else:
        action = "[FAILED]  Key Generation Failed"
        color = "\033[91m"

    print(f"\n{color}{action}\033[0m")
    print(f"    ├─ PID:          {evt.pid} ({proc_name})")
    print(f"    ├─ Container ID: {container_id}") # Updated output
    print(f"    ├─ Cgroup ID:    {evt.cgroup_id}")
    print(f"    └─ Algo:         {algo_name}")
    print("-" * 60)

b["qfense_events"].open_perf_buffer(handle_event)
print("[*] Engine active. Waiting for OpenSSL activity...")

try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("\n[*] Detaching probes.")
