#!/usr/bin/env python3
from bcc import BPF
import ctypes

print("=" * 60)
print("[*] QFense Enterprise Agent: Semantic Discovery Engine")
print("=" * 60)

# Load the C code
with open("probe.c", "r") as f:
    bpf_text = f.read()

b = BPF(text=bpf_text)

# Attach the three distinct hooks
print("[*] Attaching Context Probe...")
b.attach_uprobe(name="crypto", sym="EVP_PKEY_CTX_new_from_name", fn_name="probe_evp_context")

print("[*] Attaching Keygen Entry Probe...")
b.attach_uprobe(name="crypto", sym="EVP_PKEY_generate", fn_name="probe_evp_keygen_entry")

print("[*] Attaching Keygen Return Probe...")
b.attach_uretprobe(name="crypto", sym="EVP_PKEY_generate", fn_name="probe_evp_keygen_return")

# Must match the C struct exactly. 
# Note: We add _pack_ = 1 to ensure Python and C align memory strictly.
class CryptoEvent(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("cgroup_id", ctypes.c_uint64),
        ("pid", ctypes.c_uint32),
        ("event_type", ctypes.c_uint8),
        ("comm", ctypes.c_char * 16),
        ("algo_name", ctypes.c_char * 32)
    ]

def handle_event(cpu, data, size):
    evt = ctypes.cast(data, ctypes.POINTER(CryptoEvent)).contents
    proc_name = evt.comm.decode('utf-8', 'replace')
    algo_name = evt.algo_name.decode('utf-8', 'replace') or "Unknown"
    
    # Determine what actually happened based on the event_type
    if evt.event_type == 0:
        action = "[CONTEXT] Algorithm Requested"
        color = "\033[93m" # Yellow
    elif evt.event_type == 1:
        action = "[ACTION]  Key Generation Initiated"
        color = "\033[96m" # Cyan
    elif evt.event_type == 2:
        action = "[SUCCESS] Key Generated Successfully"
        color = "\033[92m" # Green
    else:
        action = "[FAILED]  Key Generation Failed"
        color = "\033[91m" # Red

    print(f"\n{color}{action}\033[0m")
    print(f"    ├─ PID:      {evt.pid} ({proc_name})")
    print(f"    ├─ Cgroup:   {evt.cgroup_id}")
    print(f"    └─ Algo:     {algo_name}")
    print("-" * 60)

b["qfense_events"].open_perf_buffer(handle_event)
print("[*] Engine active. Waiting for OpenSSL activity...")

try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("\n[*] Detaching probes.")
