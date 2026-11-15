#!/bin/bash
echo "=== BASELINE (No Agent) ==="
sudo kubectl scale daemonset qfense-agent -n kube-system --replicas=0
sleep 3
for i in {1..5}; do
    /usr/bin/time -f "Run $i: %e seconds" bash -c 'for j in {1..100}; do openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out /dev/null; done'
done

echo -e "\n=== ACTIVE (With Agent) ==="
sudo kubectl scale daemonset qfense-agent -n kube-system --replicas=1
sleep 5
for i in {1..5}; do
    /usr/bin/time -f "Run $i: %e seconds" bash -c 'for j in {1..100}; do openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out /dev/null; done'
done
