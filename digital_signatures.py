"""
BIT4138 Advanced Cryptography - Week 7
Digital Signatures and Certificate Management
Student: Kevin Mburu Gitau | BSCCS/2024/58901

Requirements: pip install cryptography
"""

import os
import datetime
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID


# ─────────────────────────────────────────────
# Fig 1: Digital Signature Generation
# ─────────────────────────────────────────────

def generate_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return private_key, private_key.public_key()

def sign_document(document: str, private_key) -> bytes:
    signature = private_key.sign(
        document.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def show_signature(document: str, private_key):
    print(f"\n[Digital Signature Generation]")
    print(f"  Document     : {document}")
    print(f"  Algorithm    : RSA-2048 with PSS padding + SHA-256")
    signature = sign_document(document, private_key)
    print(f"  Signature    : {signature.hex()[:64]}... ({len(signature)} bytes)")
    print(f"  Signed       : SUCCESS ✓")
    return signature


# ─────────────────────────────────────────────
# Fig 2: Signature Verification Process
# ─────────────────────────────────────────────

def verify_signature(document: str, signature: bytes, public_key) -> bool:
    try:
        public_key.verify(
            signature,
            document.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

def signature_verification_demo(document: str, signature: bytes, private_key, public_key):
    print(f"\n[Signature Verification Process]")

    # Test 1: Correct document + correct key
    result1 = verify_signature(document, signature, public_key)
    print(f"  Test 1 — Original document, correct key : {'VALID ✓' if result1 else 'INVALID ✗'}")

    # Test 2: Tampered document
    tampered = document + " (tampered)"
    result2 = verify_signature(tampered, signature, public_key)
    print(f"  Test 2 — Tampered document              : {'VALID ✓' if result2 else 'INVALID ✗ (correctly rejected)'}")

    # Test 3: Wrong key
    _, other_pub = generate_keypair()
    result3 = verify_signature(document, signature, other_pub)
    print(f"  Test 3 — Wrong public key               : {'VALID ✓' if result3 else 'INVALID ✗ (correctly rejected)'}")

    print(f"\n  Conclusion: Only the original document with the matching")
    print(f"  public key passes verification — integrity confirmed.")


# ─────────────────────────────────────────────
# Fig 3: Certificate Creation Using OpenSSL (Python)
# ─────────────────────────────────────────────

def create_self_signed_cert(private_key, common_name="Kevin Mburu Gitau",
                             org="Mount Kenya University", country="KE"):
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(private_key, hashes.SHA256(), default_backend())
    )

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)

    print(f"\n[Certificate Creation]")
    print(f"  Common Name  : {common_name}")
    print(f"  Organisation : {org}")
    print(f"  Country      : {country}")
    print(f"  Valid From   : {cert.not_valid_before_utc.strftime('%Y-%m-%d')}")
    print(f"  Valid Until  : {cert.not_valid_after_utc.strftime('%Y-%m-%d')}")
    print(f"  Serial No.   : {cert.serial_number}")
    print(f"\n  --- Certificate PEM Preview ---")
    lines = cert_pem.decode().split('\n')
    for line in lines[:6]:
        print(f"  {line}")
    print(f"  ...")

    with open("certificate.pem", 'wb') as f:
        f.write(cert_pem)
    print(f"\n  Saved to     : certificate.pem")

    return cert


# ─────────────────────────────────────────────
# Fig 4: Secure Document Validation
# ─────────────────────────────────────────────

def secure_document_validation(private_key, public_key):
    print(f"\n[Secure Document Validation]")
    doc = input("  Enter document content to sign: ").strip()
    if not doc:
        doc = "BIT4138 Assignment Submission - Kevin Mburu Gitau - 2024"

    print(f"\n  [Sender] Signing document with private key...")
    signature = sign_document(doc, private_key)
    print(f"  Signature    : {signature.hex()[:48]}...")

    print(f"\n  [Receiver] Verifying signature with public key...")
    valid = verify_signature(doc, signature, public_key)
    print(f"  Document     : {doc}")
    print(f"  Integrity    : {'VERIFIED ✓ — document is authentic and untampered' if valid else 'FAILED ✗'}")


# ─────────────────────────────────────────────
# Fig 5: Certificate Testing Results
# ─────────────────────────────────────────────

def certificate_testing(cert, private_key, public_key):
    print(f"\n[Certificate Testing Results]")

    # Test 1: Certificate validity period
    now = datetime.datetime.now(datetime.timezone.utc)
    valid_period = cert.not_valid_before_utc <= now <= cert.not_valid_after_utc
    print(f"  Test 1 — Validity period check     : {'PASS ✓' if valid_period else 'FAIL ✗'}")

    # Test 2: Public key matches private key
    cert_pub_numbers = cert.public_key().public_numbers()
    our_pub_numbers = public_key.public_numbers()
    key_match = cert_pub_numbers.n == our_pub_numbers.n
    print(f"  Test 2 — Public key matches cert   : {'PASS ✓' if key_match else 'FAIL ✗'}")

    # Test 3: Sign and verify using cert's public key
    test_msg = "Certificate validation test message"
    sig = sign_document(test_msg, private_key)
    verified = verify_signature(test_msg, sig, cert.public_key())
    print(f"  Test 3 — Sign/verify with cert key : {'PASS ✓' if verified else 'FAIL ✗'}")

    # Test 4: Serial number present
    print(f"  Test 4 — Serial number present     : {'PASS ✓' if cert.serial_number else 'FAIL ✗'}")

    # Test 5: Subject info
    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    print(f"  Test 5 — Subject CN readable       : PASS ✓ ({cn})")

    print(f"\n  All certificate tests complete.")


# ─────────────────────────────────────────────
# Interactive Menu
# ─────────────────────────────────────────────

def main():
    print("="*55)
    print("   BIT4138 - Week 7: Digital Signatures & Certificates")
    print("   Student: Kevin Mburu Gitau | BSCCS/2024/58901")
    print("="*55)

    print("\n  Generating RSA-2048 key pair...")
    private_key, public_key = generate_keypair()
    print("  Key pair ready ✓")

    last_signature = None
    last_document = None
    last_cert = None

    while True:
        print("\nOptions:")
        print("  1. Generate a Digital Signature (Fig 1)")
        print("  2. Verify Signature (Fig 2)")
        print("  3. Create Self-Signed Certificate (Fig 3)")
        print("  4. Secure Document Validation (Fig 4)")
        print("  5. Certificate Testing Results (Fig 5)")
        print("  6. Generate new key pair")
        print("  7. Exit")

        choice = input("\nSelect option: ").strip()

        if choice == '1':
            doc = input("  Enter document to sign: ").strip() or "BIT4138 Cryptography Document"
            last_document = doc
            last_signature = show_signature(doc, private_key)

        elif choice == '2':
            if not last_signature:
                print("  [!] No signature yet. Use option 1 first.")
            else:
                signature_verification_demo(last_document, last_signature, private_key, public_key)

        elif choice == '3':
            cn   = input("  Common Name (your name) [Kevin Mburu Gitau]: ").strip() or "Kevin Mburu Gitau"
            org  = input("  Organisation [Mount Kenya University]: ").strip() or "Mount Kenya University"
            country = input("  Country code [KE]: ").strip() or "KE"
            last_cert = create_self_signed_cert(private_key, cn, org, country)

        elif choice == '4':
            secure_document_validation(private_key, public_key)

        elif choice == '5':
            if not last_cert:
                print("  [!] No certificate yet. Use option 3 first.")
            else:
                certificate_testing(last_cert, private_key, public_key)

        elif choice == '6':
            private_key, public_key = generate_keypair()
            last_signature = None
            last_document = None
            last_cert = None
            print("  New key pair generated ✓")

        elif choice == '7':
            if os.path.exists("certificate.pem"):
                os.remove("certificate.pem")
            print("\n[*] Exiting. Goodbye!")
            break

        else:
            print("  [!] Invalid option. Try again.")


if __name__ == "__main__":
    main()
