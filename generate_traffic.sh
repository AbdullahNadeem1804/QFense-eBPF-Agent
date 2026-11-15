#!/bin/bash
echo "Generating crypto traffic every 3 seconds (Press Ctrl+C to stop)..."
while true; do
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out /dev/null
    sleep 3
done
