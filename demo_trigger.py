import time
import requests
from cryptography.hazmat.primitives.asymmetric import rsa, ec

print("="*50)
print("[*] QFense Live Demo Trigger Initiated")
print("="*50)

for i in range(1, 11):
    print(f"\n[+] Cycle {i}/10")
    
    # 1. Trigger Vulnerable Memory Generation
    print(" ├─ Generating legacy RSA-2048 key in memory...")
    rsa.generate_private_key(public_exponent=65537, key_size=2048)
    time.sleep(0.5)
    
    print(" ├─ Generating legacy ECC (SECP256R1) key in memory...")
    ec.generate_private_key(ec.SECP256R1())
    time.sleep(0.5)

    # 2. Trigger Post-Quantum TLS & Network Socket Correlation
    print(" └─ Executing external TLS handshake to Cloudflare...")
    try:
        requests.get("https://cloudflare.com", timeout=3)
    except Exception as e:
        pass
        
    time.sleep(1.5) # Pause to let the dashboard UI breathe

print("\n[*] Demo sequence complete.")