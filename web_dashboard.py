#!/usr/bin/env python3
import json
import sqlite3
import datetime
import jsonschema
from flask import Flask, render_template, Response, jsonify, request
import queue

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

# --- Risk Engine ---
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

# --- Flask Routes ---
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
    
    risk, reason = calculate_risk(algo, action)
    
    payload = {
        "pid": data.get('pid'), "proc": data.get('proc'), "algo": algo,
        "event_type": data.get('event_type'), "action": action, 
        "container": data.get('container', 'Unresolved'),
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
        # Don't fake key length if we don't have it
        components.append({
            "type": "cryptographic-asset",
            "name": f"process-{row['pid']}-cgroup-{row['container_id']}",
            "cryptoProperties": {
                "assetType": "algorithm",
                "algorithmProperties": {"algorithmFamily": row['algorithm']}
            }
        })
    cbom = {
        "bomFormat": "CycloneDX", "specVersion": "1.7",
        "metadata": {"timestamp": datetime.datetime.utcnow().isoformat() + "Z", "component": {"type": "application", "name": "QFense-eBPF-Agent"}},
        "components": components
    }
    return Response(json.dumps(cbom, indent=2), mimetype="application/json", headers={"Content-Disposition": "attachment;filename=qfense_cbom.json"})

if __name__ == '__main__':
    print("[*] Starting QFense Control Plane on port 5000...")
    app.run(host='0.0.0.0', port=5000, threaded=True)
