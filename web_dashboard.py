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
from flask import Flask, render_template, Response, jsonify, request
from bcc import BPF

parser = argparse.ArgumentParser()
parser.add_argument("--lib", type=str, default="crypto")
args = parser.parse_args()

app = Flask(__name__)
event_queue = queue.Queue()
DB_FILE = "qfense.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("""
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        observed_at TEXT, pid INTEGER, process_name TEXT,
        container_id TEXT, event_type INTEGER, action TEXT,
        algorithm TEXT, risk TEXT, reason TEXT
    )""")
    conn.commit()
    conn.close()
init_db()

def save_event_to_db(payload):
    conn = sqlite3.connect(DB_FILE)
    conn.execute("""
        INSERT INTO events (observed_at, pid, process_name, container_id, event_type, action, algorithm, risk, reason)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        datetime.datetime.utcnow().isoformat() + "Z",
        payload.get("pid"), payload.get("proc"), payload.get("container"),
        payload.get("event_type"), payload.get("action"), payload.get("algo"),
        payload.get("risk", "INFO"), payload.get("reason", "")
    ))
    conn.commit()
    conn.close()

def calculate_risk(algo, action):
    algo_upper = str(algo).upper()
    if any(pqc in algo_upper for pqc in ["ML-KEM", "KYBER", "ML-DSA", "DILITHIUM", "SLH-DSA", "FALCON"]):
        return "PQC_OBSERVED", "Post-quantum family observed"
    if action == "Context Created":
        return "INFO", "Algorithm context requested (no key generated)"
    if action == "Keygen Failed":
        return "INFO", "Key generation failed"
    if action == "Keygen Started":
        if "RSA" in algo_upper: return "MEDIUM", "RSA keygen initiated"
        if any(ec in algo_upper for ec in ["EC", "X25519"]): return "MEDIUM", "EC keygen initiated"
    if action == "Keygen Success":
        if "RSA" in algo_upper: return "HIGH", "Quantum-vulnerable RSA key generated"
        if any(ec in algo_upper for ec in ["EC", "X25519"]): return "MEDIUM", "Quantum-vulnerable EC key generated"
    return "INFO", f"Unclassified: {algo}"

print(f"[*] Compiling eBPF Probe for target library: {args.lib}")
with open("agent/probe.c", "r") as f:
    bpf_text = f.read()
b = BPF(text=bpf_text)
try:
    b.attach_uprobe(name=args.lib, sym="EVP_PKEY_CTX_new_from_name", fn_name="probe_evp_context")
    b.attach_uprobe(name=args.lib, sym="EVP_PKEY_generate", fn_name="probe_evp_keygen_entry")
    b.attach_uretprobe(name=args.lib, sym="EVP_PKEY_generate", fn_name="probe_evp_keygen_return")
    print("[*] Probes attached successfully!")
except Exception as e:
    print(f"[!] Error: {e}")
    exit(1)

class CryptoEvent(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("cgroup_id", ctypes.c_uint64), ("pid", ctypes.c_uint32), ("event_type", ctypes.c_uint8), ("comm", ctypes.c_char * 16), ("algo_name", ctypes.c_char * 32)]

def get_container_id(pid):
    try:
        with open(f"/proc/{pid}/cgroup", "r") as f:
            cgroup_path = f.read()
        match = re.search(r'(?:docker|containerd|cri-containerd|cri-o)-([a-f0-9]{64})', cgroup_path)
        if match: return match.group(1)[:12]
    except FileNotFoundError:
        pass
    return "Host Process"

def handle_event(cpu, data, size):
    evt = ctypes.cast(data, ctypes.POINTER(CryptoEvent)).contents
    action_name = "Context Created" if evt.event_type == 0 else "Keygen Started" if evt.event_type == 1 else "Keygen Success" if evt.event_type == 2 else "Keygen Failed"
    algo_name = evt.algo_name.decode('utf-8', 'replace') or "Unknown"
    risk, reason = calculate_risk(algo_name, action_name)
    
    payload = {
        "pid": evt.pid, "proc": evt.comm.decode('utf-8', 'replace'), "algo": algo_name,
        "event_type": evt.event_type, "action": action_name, "container": get_container_id(evt.pid),
        "risk": risk, "reason": reason
    }
    save_event_to_db(payload)
    event_queue.put(payload)

b["qfense_events"].open_perf_buffer(handle_event)
threading.Thread(target=lambda: [b.perf_buffer_poll() for _ in iter(int, 1)], daemon=True).start()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/v1/events')
def get_events():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM events ORDER BY id DESC LIMIT 50").fetchall()
    conn.close()
    return jsonify([dict(row) for row in rows])

@app.route('/api/v1/ingest', methods=['POST'])
def ingest_event():
    data = request.json
    algo = data.get('algo', 'Unknown')
    action = data.get('action', 'Unknown')
    
    # THIS IS THE CRITICAL FIX FOR THE BRIDGE
    risk, reason = calculate_risk(algo, action)
    
    payload = {
        "pid": data.get('pid'), "proc": data.get('proc'), "algo": algo,
        "event_type": data.get('event_type'), "action": action, "container": data.get('container', 'K8s Host'),
        "risk": risk, "reason": reason
    }
    save_event_to_db(payload)
    event_queue.put(payload)
    return jsonify({"status": "success"}), 200

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
    rows = conn.execute("SELECT * FROM events WHERE action = 'Keygen Success' ORDER BY id DESC LIMIT 50").fetchall()
    conn.close()
    components = []
    for row in rows:
        components.append({
            "type": "cryptographic-asset",
            "name": f"process-{row['pid']}-cgroup-{row['container_id']}",
            "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": {"algorithmFamily": row['algorithm'], "keyLength": 2048}}
        })
    cbom = {
        "bomFormat": "CycloneDX", "specVersion": "1.7",
        "metadata": {"timestamp": datetime.datetime.utcnow().isoformat() + "Z", "component": {"type": "application", "name": "QFense-eBPF-Agent"}},
        "components": components
    }
    return Response(json.dumps(cbom, indent=2), mimetype="application/json", headers={"Content-Disposition": "attachment;filename=qfense_cbom.json"})

if __name__ == '__main__':
    print("[*] Starting QFense Web Dashboard on port 5000...")
    app.run(host='0.0.0.0', port=5000, threaded=True)
