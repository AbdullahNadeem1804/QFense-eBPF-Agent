import subprocess
import json
import requests
import re

def resolve_container_id(pid):
    try:
        with open(f"/proc/{pid}/cgroup", "r") as f:
            cgroup_path = f.read().strip()
        
        match = re.search(r'(?:docker|containerd|cri-containerd|cri-o)-([a-f0-9]{64})', cgroup_path)
        if match: return match.group(1)[:12]
        
        match = re.search(r'/pod[a-f0-9\-]+/([a-f0-9]{64})', cgroup_path)
        if match: return match.group(1)[:12]
        
        match = re.search(r'/([a-f0-9]{64})$', cgroup_path)
        if match: return match.group(1)[:12]
            
    except Exception:
        return "UNRESOLVED"
    
    # If we read the file but it's not a container, it's genuinely a host process
    return "Host Process"

print("[*] Starting K8s Log Bridge (JSON Mode)...")
# NO SUDO - Make sure you ran the kubeconfig fix earlier!
process = subprocess.Popen(
    ["kubectl", "logs", "-n", "kube-system", "-l", "app=qfense-agent", "-f"],
    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
)

for line in iter(process.stdout.readline, ''):
    line = line.strip()
    if not line.startswith('{'): continue 
    
    try:
        event = json.loads(line)
    except json.JSONDecodeError:
        continue
        
    event['container'] = resolve_container_id(event['pid'])
    
    try:
        response = requests.post("http://localhost:5000/api/v1/ingest", json=event, timeout=5)
        response.raise_for_status() # THIS IS THE CRITICAL FIX
        print(f"[>] Accepted: {event['action']} - {event['algo']} (Container: {event['container']})")
    except Exception as e:
        print(f"[!] Bridge error: {e}")
