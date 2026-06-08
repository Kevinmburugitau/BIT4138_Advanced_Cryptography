"""
BIT4138 Advanced Cryptography - Week 5
Public Key Cryptography: RSA Implementation
Student: Kevin Mburu Gitau | BSCCS/2024/58901

Requirements: pip install cryptography
"""

import os
import time
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend


# ─────────────────────────────────────────────
# Fig 1: RSA Key Pair Generation
# ─────────────────────────────────────────────

def generate_rsa_keypair(key_size=2048):
    print(f"\n[RSA Key Pair Generation]")
    print(f"  Generating {key_size}-bit RSA key pair...")
    start = time.time()
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    elapsed = (time.time() - start) * 1000
    pub_numbers = public_key.public_numbers()
    print(f"  Key size        : {key_size} bits")
    print(f"  Public exponent : 65537")
    print(f"  Generated in    : {elapsed:.2f} ms")
    print(f"  Public key (n)  : {str(pub_numbers.n)[:48]}... (truncated)")
    return private_key, public_key


def save_keys(private_key, public_key):
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open("private_key.pem", 'wb') as f: f.write(priv_pem)
    with open("public_key.pem", 'wb') as f: f.write(pub_pem)
    print(f"\n  Private key saved → private_key.pem")
    print(f"  Public key saved  → public_key.pem")
    print(f"\n  --- Public Key Preview ---")
    print('\n'.join(pub_pem.decode().split('\n')[:5]) + "\n  ...")


# ─────────────────────────────────────────────
# Fig 2 & 3: Encrypt / Decrypt
# ─────────────────────────────────────────────

def rsa_encrypt(message: bytes, public_key) -> bytes:
    return public_key.encrypt(
        message,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def rsa_decrypt(ciphertext: bytes, private_key) -> bytes:
    return private_key.decrypt(
        ciphertext,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


# ─────────────────────────────────────────────
# Fig 5: Validation Tests
# ─────────────────────────────────────────────

def rsa_validation_tests(private_key, public_key):
    print("\n[RSA Testing and Validation]")
    msg = b"BIT4138 RSA Validation Test"

    ct = rsa_encrypt(msg, public_key)
    dt = rsa_decrypt(ct, private_key)
    print(f"  Test 1 - Basic encrypt/decrypt     : {'PASS ✓' if msg == dt else 'FAIL ✗'}")

    try:
        other_priv, _ = generate_rsa_keypair(2048)
        rsa_decrypt(ct, other_priv)
        print(f"  Test 2 - Wrong key rejection       : FAIL ✗")
    except Exception:
        print(f"  Test 2 - Wrong key rejection       : PASS ✓ (correctly rejected)")

    ct1 = rsa_encrypt(msg, public_key)
    ct2 = rsa_encrypt(msg, public_key)
    print(f"  Test 3 - Ciphertext randomness     : {'PASS ✓' if ct1 != ct2 else 'FAIL ✗'}")

    print(f"\n  [Performance]")
    for ks in [1024, 2048]:
        priv, pub = generate_rsa_keypair(ks)
        data = b"Benchmark."
        start = time.time()
        for _ in range(5):
            ct = rsa_encrypt(data, pub)
            rsa_decrypt(ct, priv)
        avg = (time.time() - start) / 5 * 1000
        print(f"    {ks}-bit RSA avg : {avg:.2f} ms per encrypt+decrypt")


# ─────────────────────────────────────────────
# Interactive Menus
# ─────────────────────────────────────────────

def encrypt_menu(private_key, public_key):
    print("\n--- RSA Encryption ---")
    message = input("  Enter message to encrypt: ").strip()
    if not message:
        print("  [!] Using default message.")
        message = "Secure RSA Message - BIT4138"

    plaintext = message.encode()
    ciphertext = rsa_encrypt(plaintext, public_key)
    decrypted = rsa_decrypt(ciphertext, private_key)

    print(f"\n  [Public Key Encryption]")
    print(f"  Original        : {message}")
    print(f"  Ciphertext (hex): {ciphertext.hex()[:56]}...")

    print(f"\n  [Private Key Decryption]")
    print(f"  Decrypted       : {decrypted.decode()}")
    print(f"  Integrity Check : {'PASS ✓' if plaintext == decrypted else 'FAIL ✗'}")


def secure_transmission_demo(private_key, public_key):
    print("\n--- Secure Message Transmission Demo ---")
    sender_msg = input("  Enter message to send securely: ").strip()
    if not sender_msg:
        sender_msg = "Hello! This is a secret RSA message."

    print(f"\n  [Sender] Encrypting with recipient's public key...")
    ciphertext = rsa_encrypt(sender_msg.encode(), public_key)
    print(f"  Ciphertext      : {ciphertext.hex()[:56]}...")

    print(f"\n  [Receiver] Decrypting with private key...")
    decrypted = rsa_decrypt(ciphertext, private_key)
    print(f"  Decrypted       : {decrypted.decode()}")
    print(f"  Secure delivery : {'SUCCESS ✓' if sender_msg == decrypted.decode() else 'FAILED ✗'}")


def main():
    print("="*55)
    print("   BIT4138 - Week 5: RSA Public Key Cryptography")
    print("   Student: Kevin Mburu Gitau | BSCCS/2024/58901")
    print("="*55)

    print("\nChoose RSA key size:")
    print("  1. 1024-bit (fast, less secure)")
    print("  2. 2048-bit (recommended)")
    ks_choice = input("Select: ").strip()
    key_size = 1024 if ks_choice == '1' else 2048
    private_key, public_key = generate_rsa_keypair(key_size)
    save_keys(private_key, public_key)

    while True:
        print("\nOptions:")
        print("  1. Encrypt / Decrypt a message")
        print("  2. Secure message transmission demo")
        print("  3. Run validation tests")
        print("  4. Generate new key pair")
        print("  5. Exit")

        choice = input("\nSelect option: ").strip()

        if choice == '1':
            encrypt_menu(private_key, public_key)
        elif choice == '2':
            secure_transmission_demo(private_key, public_key)
        elif choice == '3':
            rsa_validation_tests(private_key, public_key)
        elif choice == '4':
            private_key, public_key = generate_rsa_keypair(key_size)
            save_keys(private_key, public_key)
        elif choice == '5':
            for f in ["private_key.pem", "public_key.pem"]:
                if os.path.exists(f): os.remove(f)
            print("\n[*] Exiting. Goodbye!")
            break
        else:
            print("[!] Invalid option. Try again.")


if __name__ == "__main__":
    main()
