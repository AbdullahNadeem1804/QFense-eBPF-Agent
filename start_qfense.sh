#!/bin/bash
echo "=== Starting QFense Stack ==="

# 1. Start K3s Agent
sudo systemctl start k3s
sleep 5
sudo kubectl apply -f daemonset.yaml

# 2. Start Flask Dashboard in background
echo "Starting Dashboard..."
sudo nohup python3 web_dashboard.py > dashboard.log 2>&1 &

# 3. Start Bridge in background
echo "Starting Bridge..."
sudo nohup python3 bridge.py > bridge.log 2>&1 &

# 4. Start Traffic Generator
echo "Starting Traffic Generator..."
nohup ./generate_traffic.sh > traffic.log 2>&1 &

echo "=== QFense is Live! ==="
echo "Dashboard: http://$(hostname -I | awk '{print $1}'):5000"
echo "To view logs, run: tail -f dashboard.log bridge.log"
