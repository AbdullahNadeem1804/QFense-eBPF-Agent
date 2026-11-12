#!/usr/bin/env python3
import threading
import queue
import json
import ctypes
import re
import sqlite3
import datetime
import argparse
import jsonschema
from flask import Flask, render_template, Response, jsonify
from bcc import BPF

parser = argparse.ArgumentParser()
parser.add_argument("--lib", type=str, default="crypto", help="Path to libcrypto.so.3")
args = parser.parse_args()

app = Flask(__name__)
event_queue = queue.Queue()
DB_FILE = "qfense.db"

# --- Database Setup ---
def init_db():
    conn = sqlite3.connect(DB_FILE)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("""
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        observed_at TEXT,
        pid INTEGER,
        process_name TEXT,
        container_id TEXT,
        event_type INTEGER,
        action TEXT,
        algorithm TEXT
    )
    """)
    conn.commit()
    conn.close()

init_db()

def save_event_to_db(payload):
    conn = sqlite3.connect(DB_FILE)
    conn.execute("""
        INSERT INTO events (observed_at, pid, process_name, container_id, event_type, action, algorithm)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        datetime.datetime.utcnow().isoformat() + "Z",
        payload["pid"],
        payload["proc"],
        payload["container"],
        payload["event_type"],
        payload["action"],
        payload["algo"]
    ))
    conn.commit()
    conn.close()

# --- eBPF Setup ---
print(f"[*] Compiling eBPF Probe for target library: {args.lib}")
with open("agent/probe.c", "r") as f:
    bpf_text = f.read()

b = BPF(text=bpf_text)

try:
    print("[*] Attaching probes...")
    b.attach_uprobe(name=args.lib, sym="EVP_PKEY_CTX_new_from_name", fn_name="probe_evp_context")
    b.attach_uprobe(name=args.lib, sym="EVP_PKEY_generate", fn_name="probe_evp_keygen_entry")
    b.attach_uretprobe(name=args.lib, sym="EVP_PKEY_generate", fn_name="probe_evp_keygen_return")
    print("[*] Probes attached successfully!")
except Exception as e:
    print(f"[!] Error attaching probes: {e}")
    exit(1)

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
    try:
        with open(f"/proc/{pid}/cgroup", "r") as f:
            cgroup_path = f.read()
        match = re.search(r'(?:docker|containerd)-([a-f0-9]{64})', cgroup_path)
        if match:
            return match.group(1)[:12]
    except FileNotFoundError:
        pass
    return "Host Process"

def handle_event(cpu, data, size):
    evt = ctypes.cast(data, ctypes.POINTER(CryptoEvent)).contents
    proc_name = evt.comm.decode('utf-8', 'replace')
    algo_name = evt.algo_name.decode('utf-8', 'replace') or "Unknown"
    
    action_name = "Context Created"
    if evt.event_type == 1: action_name = "Keygen Started"
    elif evt.event_type == 2: action_name = "Keygen Success"
    elif evt.event_type == 3: action_name = "Keygen Failed"

    payload = {
        "pid": evt.pid,
        "proc": proc_name,
        "algo": algo_name,
        "event_type": evt.event_type,
        "action": action_name,
        "container": get_container_id(evt.pid)
    }
    
    save_event_to_db(payload)
    event_queue.put(payload)

b["qfense_events"].open_perf_buffer(handle_event)

def poll_ebpf():
    while True:
        b.perf_buffer_poll()

threading.Thread(target=poll_ebpf, daemon=True).start()

# --- Flask Routes ---
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/v1/events')
def get_events():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.execute("SELECT * FROM events ORDER BY id DESC LIMIT 50")
    rows = cursor.fetchall()
    conn.close()
    return jsonify([dict(row) for row in rows])

@app.route('/stream')
def stream():
    def event_stream():
        while True:
            data = event_queue.get()
            yield f"data: {json.dumps(data)}\n\n"
    return Response(event_stream(), mimetype="text/event-stream")

@app.route('/export-cbom')
def export_cbom():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.execute("SELECT * FROM events ORDER BY id DESC LIMIT 50")
    rows = cursor.fetchall()
    conn.close()

    components = []
    for row in rows:
        components.append({
            "type": "cryptographic-asset",
            "name": f"process-{row['pid']}-cgroup-{row['container_id']}",
            "cryptoProperties": {
                "assetType": "algorithm",
                "algorithmProperties": {
                    "algorithmFamily": row['algorithm'],
                    "keyLength": 2048
                }
            }
        })

    cbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "metadata": {
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "component": {"type": "application", "name": "QFense-eBPF-Agent"}
        },
        "components": components
    }

    schema = {
        "type": "object",
        "properties": {
            "bomFormat": {"type": "string", "enum": ["CycloneDX"]},
            "specVersion": {"type": "string"},
            "components": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["type", "name", "cryptoProperties"],
                    "properties": {
                        "type": {"type": "string", "enum": ["cryptographic-asset"]},
                        "cryptoProperties": {"type": "object"}
                    }
                }
            }
        },
        "required": ["bomFormat", "specVersion", "components"]
    }

    try:
        jsonschema.validate(instance=cbom, schema=schema)
        print("[*] CBOM passed strict CycloneDX schema validation.")
    except jsonschema.exceptions.ValidationError as e:
        print(f"[!] CBOM Validation Failed: {e}")
        return "CBOM generation failed validation", 500

    return Response(json.dumps(cbom, indent=2), mimetype="application/json", headers={"Content-Disposition": "attachment;filename=qfense_cbom.json"})

if __name__ == '__main__':
    print("[*] Starting QFense Web Dashboard on port 5000...")
    app.run(host='0.0.0.0', port=5000, threaded=True)
