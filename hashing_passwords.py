"""
BIT4138 Advanced Cryptography - Week 6
Hashing and Password Security: SHA-256 & Authentication System
Student: Kevin Mburu Gitau | BSCCS/2024/58901

Requirements: pip install bcrypt cryptography
"""

import hashlib
import hmac
import os
import time
import json
import bcrypt


# ─────────────────────────────────────────────
# Fig 1: SHA-256 Hash Generation
# ─────────────────────────────────────────────

def sha256_hash(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()

def show_hash_properties(message: str):
    print("\n[SHA-256 Hash Generation]")
    print(f"  Input        : {message}")
    h = sha256_hash(message)
    print(f"  SHA-256      : {h}")
    print(f"  Length       : {len(h)} hex chars = 256 bits")

    # Avalanche effect — tiny change, completely different hash
    modified = message[:-1] + ('a' if message[-1] != 'a' else 'b')
    h2 = sha256_hash(modified)
    print(f"\n  [Avalanche Effect]")
    print(f"  Input (mod)  : {modified}")
    print(f"  SHA-256      : {h2}")
    print(f"  Same hash?   : {h == h2}")


# ─────────────────────────────────────────────
# Fig 2: Password Hashing System
# ─────────────────────────────────────────────

# Simulated user database (in-memory)
USER_DB = {}

def hash_password(password: str) -> bytes:
    """bcrypt automatically generates and embeds a salt."""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))

def register_user(username: str, password: str):
    if username in USER_DB:
        print(f"  [!] Username '{username}' already exists.")
        return False
    hashed = hash_password(password)
    USER_DB[username] = hashed
    print(f"\n  [Password Hashing System]")
    print(f"  Username     : {username}")
    print(f"  Plain text   : {'*' * len(password)} (never stored)")
    print(f"  bcrypt hash  : {hashed.decode()}")
    print(f"  Registered   : SUCCESS ✓")
    return True


# ─────────────────────────────────────────────
# Fig 3: Login Authentication Workflow
# ─────────────────────────────────────────────

def login_user(username: str, password: str) -> bool:
    print(f"\n  [Login Authentication Workflow]")
    print(f"  Username     : {username}")
    print(f"  Step 1: Look up user in database...")

    if username not in USER_DB:
        print(f"  Result       : FAILED ✗ (user not found)")
        return False

    print(f"  Step 2: Hash the provided password...")
    print(f"  Step 3: Compare with stored hash using bcrypt...")
    time.sleep(0.3)  # Simulate computation time

    match = bcrypt.checkpw(password.encode(), USER_DB[username])
    print(f"  Step 4: Decision → {'GRANTED ✓' if match else 'DENIED ✗'}")
    return match


# ─────────────────────────────────────────────
# Fig 4: Hash Verification Results
# ─────────────────────────────────────────────

def hash_verification_demo():
    print("\n[Hash Verification Results]")
    test_cases = [
        ("hello123", "hello123", True),
        ("SecurePass!", "SecurePass!", True),
        ("password", "Password", False),
        ("BIT4138", "BIT4139", False),
    ]
    print(f"  {'Password':<15} {'Attempt':<15} {'Expected':<10} {'Result'}")
    print("  " + "-"*55)
    for pwd, attempt, expected in test_cases:
        hashed = hash_password(pwd)
        result = bcrypt.checkpw(attempt.encode(), hashed)
        status = "PASS ✓" if result == expected else "FAIL ✗"
        print(f"  {pwd:<15} {attempt:<15} {str(expected):<10} {status}")


# ─────────────────────────────────────────────
# Fig 5: Password Security Testing
# ─────────────────────────────────────────────

def password_security_test(password: str):
    print(f"\n[Password Security Testing]")
    print(f"  Password     : {password}")

    # Strength checks
    checks = {
        "Length ≥ 8"      : len(password) >= 8,
        "Has uppercase"   : any(c.isupper() for c in password),
        "Has lowercase"   : any(c.islower() for c in password),
        "Has digit"       : any(c.isdigit() for c in password),
        "Has special char": any(c in "!@#$%^&*()_+-=[]{}|;':\",./<>?" for c in password),
    }

    passed = sum(checks.values())
    for check, result in checks.items():
        print(f"  {'✓' if result else '✗'} {check}")

    strength = ["Very Weak", "Weak", "Moderate", "Strong", "Very Strong"][min(passed, 4)]
    print(f"\n  Strength     : {strength} ({passed}/5 checks passed)")

    # Simulate brute-force time estimate
    charset = 0
    if any(c.islower() for c in password): charset += 26
    if any(c.isupper() for c in password): charset += 26
    if any(c.isdigit() for c in password): charset += 10
    if any(c in "!@#$%^&*()" for c in password): charset += 10
    combinations = charset ** len(password) if charset else 1
    seconds = combinations / 1_000_000_000  # 1 billion guesses/sec
    print(f"  Combinations : {combinations:.2e}")
    print(f"  Brute-force  : ~{seconds:.2e} seconds at 1B guesses/sec")

    # SHA-256 of password (for comparison with bcrypt)
    sha = sha256_hash(password)
    print(f"\n  SHA-256 hash : {sha}")
    print(f"  bcrypt hash  : {hash_password(password).decode()}")
    print(f"  Note: bcrypt is preferred — it's slow by design and salted.")


# ─────────────────────────────────────────────
# Interactive Menu
# ─────────────────────────────────────────────

def main():
    print("="*55)
    print("   BIT4138 - Week 6: Hashing & Password Security")
    print("   Student: Kevin Mburu Gitau | BSCCS/2024/58901")
    print("="*55)

    while True:
        print("\nOptions:")
        print("  1. SHA-256 Hash Generation (Fig 1)")
        print("  2. Register a User — Password Hashing (Fig 2)")
        print("  3. Login — Authentication Workflow (Fig 3)")
        print("  4. Hash Verification Results (Fig 4)")
        print("  5. Password Security Tester (Fig 5)")
        print("  6. Exit")

        choice = input("\nSelect option: ").strip()

        if choice == '1':
            msg = input("  Enter message to hash: ").strip() or "Hello BIT4138"
            show_hash_properties(msg)

        elif choice == '2':
            username = input("  Enter username: ").strip() or "kevin"
            password = input("  Enter password: ").strip() or "Secure@2024"
            register_user(username, password)

        elif choice == '3':
            if not USER_DB:
                print("  [!] No users registered yet. Use option 2 first.")
            else:
                username = input("  Enter username: ").strip()
                password = input("  Enter password: ").strip()
                login_user(username, password)

        elif choice == '4':
            hash_verification_demo()

        elif choice == '5':
            pwd = input("  Enter password to test: ").strip() or "P@ssw0rd!"
            password_security_test(pwd)

        elif choice == '6':
            print("\n[*] Exiting. Goodbye!")
            break

        else:
            print("  [!] Invalid option. Try again.")


if __name__ == "__main__":
    main()
