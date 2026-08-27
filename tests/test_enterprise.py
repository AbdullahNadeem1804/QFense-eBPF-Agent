import requests
from cryptography.hazmat.primitives.asymmetric import rsa

print("[*] Simulating Enterprise Application Execution...")
# 1. Trigger the Uprobe (Memory Keygen)
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
print("[*] RSA 2048-bit key generated in Python memory.")

# 2. Trigger the Kprobe (TLS Network Socket)
response = requests.get("https://cloudflare.com")
print(f"[*] Secure TLS connection established with Cloudflare. Status: {response.status_code}")
