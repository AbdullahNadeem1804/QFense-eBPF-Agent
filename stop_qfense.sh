#!/bin/bash
echo "=== Stopping QFense Stack ==="
sudo pkill -f web_dashboard.py
sudo pkill -f bridge.py
sudo pkill -f generate_traffic.sh
sudo kubectl scale daemonset qfense-agent -n kube-system --replicas=0
echo "=== All services stopped. ==="
