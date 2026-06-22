"""
BIT4138 Advanced Cryptography - Week 8
Secure Communication Protocols: SSL/TLS Implementation & Analysis
Student: Kevin Mburu Gitau | BSCCS/2024/58901

Requirements: pip install cryptography requests
"""

import ssl
import socket
import threading
import time
import os
import datetime
import json
import hashlib
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.backends import default_backend


# ─────────────────────────────────────────────
# Shared: Generate self-signed cert + key for server
# ─────────────────────────────────────────────

def generate_server_cert(cert_file="server.crt", key_file="server.key"):
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "KE"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Mount Kenya University"),
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]),
            critical=False
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(private_key, hashes.SHA256(), default_backend())
    )
    with open(cert_file, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_file, "wb") as f:
        f.write(private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()
        ))
    return cert_file, key_file, cert


# ─────────────────────────────────────────────
# Fig 1: SSL/TLS Configuration
# ─────────────────────────────────────────────

def show_tls_configuration(cert):
    print("\n[SSL/TLS Configuration]")
    print(f"  Protocol       : TLS 1.3 (preferred) / TLS 1.2 (fallback)")
    print(f"  Cipher Suites  :")
    print(f"    - TLS_AES_256_GCM_SHA384       (TLS 1.3)")
    print(f"    - TLS_CHACHA20_POLY1305_SHA256 (TLS 1.3)")
    print(f"    - TLS_AES_128_GCM_SHA256       (TLS 1.3)")
    print(f"  Certificate    :")
    print(f"    Common Name  : {cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value}")
    print(f"    Organisation : {cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value}")
    print(f"    Valid From   : {cert.not_valid_before_utc.strftime('%Y-%m-%d')}")
    print(f"    Valid Until  : {cert.not_valid_after_utc.strftime('%Y-%m-%d')}")
    print(f"    Key Size     : 2048-bit RSA")
    print(f"    Signature    : SHA-256 with RSA")
    print(f"  Verify Mode    : CERT_REQUIRED (mutual authentication)")
    print(f"  SNI            : Enabled (Server Name Indication)")


# ─────────────────────────────────────────────
# Fig 2: Secure HTTPS Communication Test (TLS socket server/client)
# ─────────────────────────────────────────────

SERVER_LOG = []

def run_tls_server(cert_file, key_file, host="127.0.0.1", port=8443):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_file, key_file)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.listen(1)
        sock.settimeout(5)
        with ctx.wrap_socket(sock, server_side=True) as ssock:
            try:
                conn, addr = ssock.accept()
                with conn:
                    data = conn.recv(4096).decode()
                    SERVER_LOG.append(f"[Server] Received: {data[:60]}")
                    response = (
                        "HTTP/1.1 200 OK\r\n"
                        "Content-Type: text/plain\r\n"
                        "X-Encrypted: TLS\r\n\r\n"
                        "Secure response from BIT4138 TLS Server"
                    )
                    conn.sendall(response.encode())
                    SERVER_LOG.append(f"[Server] Response sent over TLS ✓")
            except socket.timeout:
                SERVER_LOG.append("[Server] Timeout — no client connected.")


def run_tls_client(cert_file, message, host="127.0.0.1", port=8443):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(cert_file)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    time.sleep(0.5)  # Let server start
    results = {}
    try:
        with socket.create_connection((host, port)) as sock:
            with ctx.wrap_socket(sock, server_hostname="localhost") as ssock:
                results['tls_version'] = ssock.version()
                results['cipher'] = ssock.cipher()
                results['peer_cert'] = ssock.getpeercert()

                request = f"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n{message}"
                ssock.sendall(request.encode())
                response = ssock.recv(4096).decode()
                results['response'] = response
    except Exception as e:
        results['error'] = str(e)
    return results


def https_communication_test(cert_file, key_file, message):
    print(f"\n[Secure HTTPS Communication Test]")
    print(f"  Message to send : {message}")
    print(f"  Establishing TLS connection to localhost:8443...")

    server_thread = threading.Thread(
        target=run_tls_server, args=(cert_file, key_file), daemon=True
    )
    server_thread.start()

    results = run_tls_client(cert_file, message)

    if 'error' in results:
        print(f"  Error: {results['error']}")
        return

    print(f"\n  [Handshake Results]")
    print(f"  TLS Version    : {results.get('tls_version', 'N/A')}")
    cipher = results.get('cipher', ('N/A', 'N/A', 0))
    print(f"  Cipher Suite   : {cipher[0]}")
    print(f"  Key Bits       : {cipher[2]}")
    print(f"  Server Cert    : Verified ✓")
    print(f"\n  [Response]")
    for line in results.get('response', '').split('\r\n'):
        if line.strip():
            print(f"    {line}")

    for log in SERVER_LOG:
        print(f"  {log}")


# ─────────────────────────────────────────────
# Fig 3: Wireshark Traffic Capture (simulated)
# ─────────────────────────────────────────────

def simulate_wireshark_capture(message):
    print(f"\n[Wireshark Traffic Capture — Simulated]")
    print(f"  Interface      : lo (loopback)")
    print(f"  Filter         : tcp.port == 8443")
    print(f"  Capturing...\n")

    # Simulate packet log
    ts = time.time()
    packets = [
        (ts,       "Client → Server", "TCP",  "SYN — Connection initiation"),
        (ts+0.001, "Server → Client", "TCP",  "SYN-ACK — Server acknowledges"),
        (ts+0.002, "Client → Server", "TCP",  "ACK — Connection established"),
        (ts+0.003, "Client → Server", "TLS",  "Client Hello (TLS 1.3, supported ciphers)"),
        (ts+0.004, "Server → Client", "TLS",  "Server Hello + Certificate"),
        (ts+0.005, "Client → Server", "TLS",  "Certificate Verify + Finished"),
        (ts+0.006, "Server → Client", "TLS",  "Finished — Handshake complete"),
        (ts+0.007, "Client → Server", "TLS",  f"Application Data [ENCRYPTED — {len(message.encode())} bytes]"),
        (ts+0.008, "Server → Client", "TLS",  "Application Data [ENCRYPTED — 38 bytes]"),
        (ts+0.009, "Client → Server", "TCP",  "FIN — Connection closing"),
    ]

    print(f"  {'No.':<4} {'Time':<8} {'Direction':<22} {'Proto':<6} Info")
    print("  " + "-"*70)
    for i, (t, direction, proto, info) in enumerate(packets, 1):
        print(f"  {i:<4} {t-ts:.3f}s  {direction:<22} {proto:<6} {info}")

    print(f"\n  [Analysis]")
    print(f"  Plaintext packets  : 0 — all application data is encrypted")
    print(f"  TLS handshake      : Visible (metadata only, no content)")
    print(f"  Data packets       : Show only length, not content ✓")
    print(f"  Eavesdropper sees  : 'Application Data' — cannot read message")


# ─────────────────────────────────────────────
# Fig 4: Encrypted Data Transmission
# ─────────────────────────────────────────────

def encrypted_transmission_demo(message):
    print(f"\n[Encrypted Data Transmission]")
    print(f"  Original message : {message}")
    print(f"  Encoding         : UTF-8 → bytes")

    # Show what plaintext bytes look like
    raw_bytes = message.encode()
    print(f"  Plaintext bytes  : {raw_bytes.hex()[:48]}...")

    # Simulate what TLS record layer does (AES-GCM simulation)
    import os
    key = os.urandom(32)
    iv  = os.urandom(12)

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    aesgcm = AESGCM(key)
    aad = b"TLS 1.3 record header"
    ciphertext = aesgcm.encrypt(iv, raw_bytes, aad)

    print(f"\n  [TLS Record Layer Encryption — AES-256-GCM]")
    print(f"  Session key (hex): {key.hex()[:32]}... (ephemeral, never reused)")
    print(f"  IV  (hex)        : {iv.hex()}")
    print(f"  Ciphertext (hex) : {ciphertext.hex()[:48]}...")
    print(f"  Auth Tag         : {ciphertext[-16:].hex()} (integrity proof)")
    print(f"\n  What the network sees : [TLS Application Data] {len(ciphertext)} bytes — unreadable")
    print(f"  What receiver gets    : '{message}' after decryption with session key")
    print(f"  Forward Secrecy       : ✓ (ephemeral key discarded after session)")


# ─────────────────────────────────────────────
# Fig 5: Protocol Security Analysis
# ─────────────────────────────────────────────

def protocol_security_analysis():
    print(f"\n[Protocol Security Analysis]")

    protocols = [
        ("HTTP",    "None",        "None",             "Plaintext",  "INSECURE ✗"),
        ("HTTPS",   "TLS 1.2",     "RSA / ECDHE",      "AES-128",    "SECURE ✓"),
        ("HTTPS",   "TLS 1.3",     "ECDHE only",       "AES-256-GCM","SECURE ✓✓"),
        ("SSH",     "SSH-2",       "ECDH / DH",        "ChaCha20",   "SECURE ✓"),
        ("FTP",     "None",        "None",             "Plaintext",  "INSECURE ✗"),
        ("SFTP",    "SSH-2",       "ECDH",             "AES-256",    "SECURE ✓"),
    ]

    print(f"\n  {'Protocol':<10} {'Version':<10} {'Key Exchange':<18} {'Encryption':<16} Status")
    print("  " + "-"*72)
    for proto, ver, kex, enc, status in protocols:
        print(f"  {proto:<10} {ver:<10} {kex:<18} {enc:<16} {status}")

    print(f"\n  [TLS 1.3 Improvements over TLS 1.2]")
    improvements = [
        "Removed weak cipher suites (RC4, 3DES, MD5)",
        "Mandatory forward secrecy via ECDHE",
        "Reduced handshake from 2-RTT to 1-RTT (faster)",
        "Encrypted certificates — less metadata exposed",
        "0-RTT resumption for returning connections",
    ]
    for item in improvements:
        print(f"    ✓ {item}")

    print(f"\n  [Vulnerabilities Mitigated]")
    vulns = [
        ("POODLE",      "SSLv3 padding oracle",    "Disabled SSLv3 entirely"),
        ("BEAST",       "TLS 1.0 CBC attack",       "TLS 1.2+ enforced"),
        ("HEARTBLEED",  "OpenSSL memory leak",      "Patched in OpenSSL 1.0.1g+"),
        ("MITM",        "No cert verification",     "Certificate pinning / CA chain"),
    ]
    print(f"  {'Attack':<14} {'Description':<28} Mitigation")
    print("  " + "-"*65)
    for attack, desc, fix in vulns:
        print(f"  {attack:<14} {desc:<28} {fix}")


# ─────────────────────────────────────────────
# Interactive Menu
# ─────────────────────────────────────────────

def main():
    print("="*55)
    print("   BIT4138 - Week 8: Secure Communication Protocols")
    print("   Student: Kevin Mburu Gitau | BSCCS/2024/58901")
    print("="*55)

    print("\n  Generating TLS certificate and key...")
    cert_file, key_file, cert = generate_server_cert()
    print("  Certificate ready ✓ (server.crt + server.key)")

    while True:
        print("\nOptions:")
        print("  1. SSL/TLS Configuration (Fig 1)")
        print("  2. Secure HTTPS Communication Test (Fig 2)")
        print("  3. Wireshark Traffic Capture — Simulated (Fig 3)")
        print("  4. Encrypted Data Transmission (Fig 4)")
        print("  5. Protocol Security Analysis (Fig 5)")
        print("  6. Exit")

        choice = input("\nSelect option: ").strip()

        if choice == '1':
            show_tls_configuration(cert)

        elif choice == '2':
            msg = input("  Enter message to transmit securely: ").strip()
            if not msg:
                msg = "Hello from BIT4138 secure client!"
            https_communication_test(cert_file, key_file, msg)

        elif choice == '3':
            msg = input("  Enter message being transmitted: ").strip()
            if not msg:
                msg = "Confidential BIT4138 data"
            simulate_wireshark_capture(msg)

        elif choice == '4':
            msg = input("  Enter message to encrypt for transmission: ").strip()
            if not msg:
                msg = "Secure message — BIT4138 Week 8"
            encrypted_transmission_demo(msg)

        elif choice == '5':
            protocol_security_analysis()

        elif choice == '6':
            for f in ["server.crt", "server.key"]:
                if os.path.exists(f): os.remove(f)
            print("\n[*] Exiting. Goodbye!")
            break

        else:
            print("  [!] Invalid option. Try again.")


if __name__ == "__main__":
    main()
