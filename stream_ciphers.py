"""
BIT4138 Advanced Cryptography - Week 3
Stream Ciphers and Randomness Testing: LFSR + RC4 Implementation
Student: Kevin Mburu Gitau | BSCCS/2024/58901
"""

import math
import time


# ─────────────────────────────────────────────
# Fig 1: LFSR Generator Implementation
# ─────────────────────────────────────────────

def lfsr(seed, taps, length):
    register = list(seed)
    sequence = []
    for _ in range(length):
        output_bit = register[-1]
        sequence.append(output_bit)
        feedback = 0
        for tap in taps:
            feedback ^= register[tap]
        register = [feedback] + register[:-1]
    return sequence


# ─────────────────────────────────────────────
# Fig 2: Pseudorandom Sequence Output
# ─────────────────────────────────────────────

def display_sequence(sequence, label="Sequence"):
    bits = ''.join(map(str, sequence))
    print(f"\n[{label}]")
    print(f"  Bits (first 64) : {bits[:64]}")
    print(f"  Total length    : {len(bits)} bits")
    return bits


# ─────────────────────────────────────────────
# Fig 3: Statistical Randomness Testing
# ─────────────────────────────────────────────

def randomness_tests(sequence):
    bits = ''.join(map(str, sequence))
    n = len(bits)
    ones = bits.count('1')
    zeros = bits.count('0')
    proportion_ones = ones / n

    freq_pass = abs(proportion_ones - 0.5) < 0.1

    runs = 1
    for i in range(1, len(bits)):
        if bits[i] != bits[i-1]:
            runs += 1
    expected_runs = (2 * ones * zeros) / n + 1
    runs_pass = abs(runs - expected_runs) < (n * 0.1)

    p1 = ones / n if ones > 0 else 1e-10
    p0 = zeros / n if zeros > 0 else 1e-10
    entropy = -(p1 * math.log2(p1) + p0 * math.log2(p0))

    print("\n" + "="*55)
    print("      STATISTICAL RANDOMNESS TESTING")
    print("="*55)
    print(f"  Total bits        : {n}")
    print(f"  Ones              : {ones} ({proportion_ones:.2%})")
    print(f"  Zeros             : {zeros} ({1-proportion_ones:.2%})")
    print(f"  Frequency Test    : {'PASS ✓' if freq_pass else 'FAIL ✗'}")
    print(f"  Observed Runs     : {runs}")
    print(f"  Expected Runs     : {expected_runs:.1f}")
    print(f"  Runs Test         : {'PASS ✓' if runs_pass else 'FAIL ✗'}")
    print(f"  Entropy (bits)    : {entropy:.4f} / 1.0000")
    print("="*55)


# ─────────────────────────────────────────────
# Fig 4: RC4 Stream Cipher Simulation
# ─────────────────────────────────────────────

def rc4(key, data):
    key_bytes = [ord(c) for c in key]
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key_bytes[i % len(key_bytes)]) % 256
        S[i], S[j] = S[j], S[i]

    i = j = 0
    keystream = []
    for _ in range(len(data)):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) % 256]
        keystream.append(K)

    result = bytes([ord(c) ^ k for c, k in zip(data, keystream)])
    return result, keystream


def rc4_decrypt(ciphertext_bytes, key):
    key_bytes = [ord(c) for c in key]
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key_bytes[i % len(key_bytes)]) % 256
        S[i], S[j] = S[j], S[i]

    i = j = 0
    keystream = []
    for _ in range(len(ciphertext_bytes)):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) % 256]
        keystream.append(K)

    result = bytes([b ^ k for b, k in zip(ciphertext_bytes, keystream)])
    return result


# ─────────────────────────────────────────────
# Fig 5: Encryption Performance Results
# ─────────────────────────────────────────────

def performance_test():
    print("\n[RC4 Performance Test]")
    sizes = [100, 1000, 10000]
    key = "BIT4138SecretKey"
    for size in sizes:
        data = 'A' * size
        start = time.time()
        rc4(key, data)
        elapsed = (time.time() - start) * 1000
        print(f"  {size:>6} bytes encrypted in {elapsed:.3f} ms")


# ─────────────────────────────────────────────
# Interactive Menu
# ─────────────────────────────────────────────

def lfsr_menu():
    print("\n--- LFSR Generator ---")
    seed_input = input("  Enter seed bits (e.g. 1011): ").strip()
    if not all(c in '01' for c in seed_input) or len(seed_input) < 2:
        print("  [!] Invalid seed. Using default: 1011")
        seed_input = "1011"
    seed = [int(b) for b in seed_input]

    try:
        length = int(input("  How many bits to generate? (e.g. 128): ").strip())
        if length < 8: length = 128
    except ValueError:
        length = 128

    taps = [0, len(seed) - 1]
    sequence = lfsr(seed, taps, length)
    display_sequence(sequence, "LFSR Pseudorandom Sequence")
    randomness_tests(sequence)


def rc4_menu():
    print("\n--- RC4 Stream Cipher ---")
    key = input("  Enter encryption key: ").strip()
    if not key:
        print("  [!] Empty key. Using default: SecureKey2024")
        key = "SecureKey2024"

    message = input("  Enter message to encrypt: ").strip()
    if not message:
        print("  [!] Empty message. Using default.")
        message = "Hello BIT4138!"

    print(f"\n  Key         : {key}")
    print(f"  Plaintext   : {message}")

    ciphertext, _ = rc4(key, message)
    print(f"  Ciphertext  : {ciphertext.hex()}")

    decrypted = rc4_decrypt(ciphertext, key)
    print(f"  Decrypted   : {decrypted.decode()}")
    print(f"  Match       : {message == decrypted.decode()}")


def main():
    print("="*55)
    print("   BIT4138 - Week 3: Stream Ciphers")
    print("   Student: Kevin Mburu Gitau | BSCCS/2024/58901")
    print("="*55)

    while True:
        print("\nOptions:")
        print("  1. LFSR Pseudorandom Generator")
        print("  2. RC4 Stream Cipher (Encrypt/Decrypt)")
        print("  3. RC4 Performance Test")
        print("  4. Exit")

        choice = input("\nSelect option: ").strip()

        if choice == '1':
            lfsr_menu()
        elif choice == '2':
            rc4_menu()
        elif choice == '3':
            performance_test()
        elif choice == '4':
            print("\n[*] Exiting. Goodbye!")
            break
        else:
            print("[!] Invalid option. Try again.")


if __name__ == "__main__":
    main()
