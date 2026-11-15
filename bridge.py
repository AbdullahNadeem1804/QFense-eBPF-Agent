import subprocess
import json
import requests
import re

def resolve_container_id(pid):
    try:
        with open(f"/proc/{pid}/cgroup", "r") as f:
            cgroup_path = f.read().strip()
        
        # Match Docker/containerd/cri-o IDs
        match = re.search(r'(?:docker|containerd|cri-containerd|cri-o)-([a-f0-9]{64})', cgroup_path)
        if match: return match.group(1)[:12]
        
        # Match Kubernetes Pod style
        match = re.search(r'/pod[a-f0-9\-]+/([a-f0-9]{64})', cgroup_path)
        if match: return match.group(1)[:12]
        
        # Fallback
        match = re.search(r'/([a-f0-9]{64})$', cgroup_path)
        if match: return match.group(1)[:12]
    except Exception:
        pass
    return "Host Process"

print("[*] Starting K8s Log Bridge (JSON Mode)...")
process = subprocess.Popen(
    ["kubectl", "logs", "-n", "kube-system", "-l", "app=qfense-agent", "-f"],
    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
)

for line in iter(process.stdout.readline, ''):
    line = line.strip()
    if not line.startswith('{'): continue # Skip startup logs
    
    try:
        event = json.loads(line)
    except json.JSONDecodeError:
        continue
        
    # Resolve the real container ID using the host PID
    event['container'] = resolve_container_id(event['pid'])
    
    try:
        requests.post("http://localhost:5000/api/v1/ingest", json=event, timeout=2)
        print(f"[>] Sent: {event['action']} - {event['algo']} (Container: {event['container']})")
    except Exception as e:
        print(f"[!] Bridge error: {e}")
