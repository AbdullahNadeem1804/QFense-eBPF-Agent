#!/bin/bash
sudo apt-get update && sudo apt-get install -y bpfcc-tools python3-bpfcc clang llvm python3-requests python3-cryptography
sudo mount -t tracefs nodev /sys/kernel/tracing || true
echo "[*] QFense environment ready. Run: sudo python3 agent/dashboard.py"