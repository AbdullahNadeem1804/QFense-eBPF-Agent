#!/bin/bash
echo "=== Starting QFense Enterprise Deployment ==="

# 1. Ensure K3s is running
sudo systemctl start k3s
sleep 5

# 2. Apply the DaemonSet
sudo kubectl apply -f daemonset.yaml

# 3. Wait for it to be ready
echo "Waiting for agent to start..."
sudo kubectl rollout status daemonset/qfense-agent -n kube-system --timeout=60s

echo "=== QFense Agent is Live! ==="
