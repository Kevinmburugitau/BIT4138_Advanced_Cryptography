"""
BIT4138 Advanced Cryptography - Week 4
Block Cipher Design and AES Implementation
Student: Kevin Mburu Gitau | BSCCS/2024/58901

Requirements: pip install cryptography
"""

import os
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend


def aes_encrypt(plaintext: bytes, key: bytes) -> tuple:
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return ciphertext, iv


def aes_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded_plaintext) + unpadder.finalize()


# ─────────────────────────────────────────────
# Fig 2: Key Generation
# ─────────────────────────────────────────────

def generate_aes_key(bits=256):
    key = os.urandom(bits // 8)
    print(f"\n[Key Generation]")
    print(f"  Key size   : {bits} bits ({bits // 8} bytes)")
    print(f"  Key (hex)  : {key.hex()}")
    return key


# ─────────────────────────────────────────────
# Fig 3: File Encryption
# ─────────────────────────────────────────────

def encrypt_file(filepath, key):
    with open(filepath, 'rb') as f:
        data = f.read()
    ciphertext, iv = aes_encrypt(data, key)
    enc_path = filepath + ".enc"
    with open(enc_path, 'wb') as f:
        f.write(iv + ciphertext)
    print(f"\n[File Encryption]")
    print(f"  Original   : {filepath} ({len(data)} bytes)")
    print(f"  Encrypted  : {enc_path} ({len(iv + ciphertext)} bytes)")
    return enc_path, key, iv


def decrypt_file(enc_filepath, key):
    with open(enc_filepath, 'rb') as f:
        data = f.read()
    iv = data[:16]
    ciphertext = data[16:]
    plaintext = aes_decrypt(ciphertext, key, iv)
    dec_path = enc_filepath.replace(".enc", ".dec.txt")
    with open(dec_path, 'wb') as f:
        f.write(plaintext)
    print(f"\n[File Decryption]")
    print(f"  Decrypted  : {dec_path} ({len(plaintext)} bytes)")
    print(f"  Content    : {plaintext.decode()[:80]}...")
    return dec_path


# ─────────────────────────────────────────────
# Fig 5: Performance Test
# ─────────────────────────────────────────────

def aes_performance_test(key):
    print("\n[AES Performance Testing]")
    sizes = [1024, 10240, 102400, 1048576]
    for size in sizes:
        data = os.urandom(size)
        start = time.time()
        ciphertext, iv = aes_encrypt(data, key)
        enc_time = (time.time() - start) * 1000
        start = time.time()
        aes_decrypt(ciphertext, key, iv)
        dec_time = (time.time() - start) * 1000
        label = f"{size // 1024}KB" if size < 1048576 else "1MB"
        print(f"  {label:>5}: Encrypt={enc_time:.2f}ms | Decrypt={dec_time:.2f}ms")


# ─────────────────────────────────────────────
# Interactive Menus
# ─────────────────────────────────────────────

def text_menu(key):
    print("\n--- AES Text Encryption ---")
    message = input("  Enter message to encrypt: ").strip()
    if not message:
        print("  [!] Using default message.")
        message = "Advanced Cryptography BIT4138"

    plaintext = message.encode()
    ciphertext, iv = aes_encrypt(plaintext, key)
    decrypted = aes_decrypt(ciphertext, key, iv)

    print(f"\n  Original   : {message}")
    print(f"  Key (hex)  : {key.hex()[:32]}... (truncated)")
    print(f"  Encrypted  : {ciphertext.hex()[:48]}...")
    print(f"  Decrypted  : {decrypted.decode()}")
    print(f"  Match      : {plaintext == decrypted}")


def file_menu(key):
    print("\n--- AES File Encryption ---")
    content = input("  Enter text content for the file: ").strip()
    if not content:
        content = "BIT4138 Advanced Cryptography - AES File Encryption Demo\nStudent: Kevin Mburu Gitau"

    filepath = "student_file.txt"
    with open(filepath, 'w') as f:
        f.write(content)

    enc_path = encrypt_file(filepath, key)[0]
    decrypt_file(enc_path, key)

    for f in [filepath, enc_path, enc_path.replace(".enc", ".dec.txt")]:
        if os.path.exists(f): os.remove(f)


def main():
    print("="*55)
    print("   BIT4138 - Week 4: AES Block Cipher")
    print("   Student: Kevin Mburu Gitau | BSCCS/2024/58901")
    print("="*55)

    # Generate key once per session
    print("\nChoose AES key size:")
    print("  1. 128-bit")
    print("  2. 192-bit")
    print("  3. 256-bit (recommended)")
    ks_choice = input("Select: ").strip()
    bits = {'1': 128, '2': 192, '3': 256}.get(ks_choice, 256)
    key = generate_aes_key(bits)

    while True:
        print("\nOptions:")
        print("  1. Encrypt / Decrypt a text message")
        print("  2. Encrypt / Decrypt a file")
        print("  3. Performance Test")
        print("  4. Generate a new key")
        print("  5. Exit")

        choice = input("\nSelect option: ").strip()

        if choice == '1':
            text_menu(key)
        elif choice == '2':
            file_menu(key)
        elif choice == '3':
            aes_performance_test(key)
        elif choice == '4':
            key = generate_aes_key(bits)
        elif choice == '5':
            print("\n[*] Exiting. Goodbye!")
            break
        else:
            print("[!] Invalid option. Try again.")


if __name__ == "__main__":
    main()
