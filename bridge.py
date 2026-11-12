import subprocess
import json
import requests
import re

print("[*] Starting K8s Log Bridge...")
print("[*] Listening to 'kubectl logs -f' and pushing to Flask...")

# Start the kubectl logs process
process = subprocess.Popen(
    ["sudo", "kubectl", "logs", "-n", "kube-system", "-l", "app=qfense-agent", "-f"],
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    text=True
)

# Regex to parse: [Keygen Success] PID: 40104 (openssl), Cgroup: 10357, Algo: RSA
pattern = re.compile(r'\[(.*?)\] PID: (\d+) \((.*?)\), Cgroup: (\d+), Algo: (.*)')

for line in iter(process.stdout.readline, ''):
    line = line.strip()
    match = pattern.search(line)
    if match:
        action = match.group(1)
        pid = match.group(2)
        proc = match.group(3)
        cgroup = match.group(4)
        algo = match.group(5)
        
        # Map action to event type
        event_type = 0
        if action == "Keygen Started": event_type = 1
        elif action == "Keygen Success": event_type = 2
        elif action == "Keygen Failed": event_type = 3

        payload = {
            "pid": int(pid),
            "proc": proc,
            "algo": algo,
            "event_type": event_type,
            "action": action,
            "container": f"cgroup-{cgroup}"
        }
        
        try:
            requests.post("http://localhost:5000/api/v1/ingest", json=payload)
            print(f"[>] Sent to Dashboard: {action} - {algo}")
        except Exception as e:
            print(f"[!] Failed to send to Flask: {e}")
