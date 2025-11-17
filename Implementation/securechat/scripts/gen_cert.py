"""
Certificate Generation Script

Issues RSA X.509 certificates for server and client, signed by the Root CA.

Security Properties:
- Certificates signed by Root CA (not self-signed)
- 2048-bit RSA keys
- BasicConstraints: CA=FALSE (end-entity certificates)
- Subject Alternative Name (SAN) for hostname binding
- 1-year validity period
- SHA-256 signature algorithm

Output:
    certs/server.key, certs/server.crt - Server identity
    certs/client.key, certs/client.crt - Client identity

Usage:
    python scripts/gen_cert.py
    
Prerequisites:
    Must run gen_ca.py first to create the Root CA.
"""

import os
import sys
import datetime
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend


# Configuration
KEY_SIZE = 2048
VALIDITY_DAYS = 365
CERTS_DIR = "certs"
COUNTRY = "PK"
ORGANIZATION = "FAST-NUCES SecureChat"


def load_ca_assets():
    """
    Loads the Root CA key and certificate.
    
    Returns:
        tuple: (ca_cert, ca_key)
        
    Raises:
        FileNotFoundError: If CA files don't exist
    """
    ca_cert_path = os.path.join(CERTS_DIR, "ca.crt")
    ca_key_path = os.path.join(CERTS_DIR, "ca.key")
    
    if not os.path.exists(ca_cert_path) or not os.path.exists(ca_key_path):
        raise FileNotFoundError(
            f"Root CA not found in '{CERTS_DIR}/'. "
            "Run 'python scripts/gen_ca.py' first."
        )
    
    # Load CA certificate
    with open(ca_cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
    
    # Load CA private key
    with open(ca_key_path, "rb") as f:
        ca_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )
    
    return ca_cert, ca_key


def generate_signed_cert(common_name: str, filename_base: str, ca_cert, ca_key):
    """
    Generates a private key and certificate signed by the Root CA.
    
    Args:
        common_name: Certificate Common Name (CN), e.g., "server", "client"
        filename_base: Output filename prefix (e.g., "server" -> server.key, server.crt)
        ca_cert: Root CA certificate object
        ca_key: Root CA private key object
        
    Steps:
    1. Generate RSA private key for the entity
    2. Build certificate with subject = entity, issuer = CA
    3. Add extensions (BasicConstraints, KeyUsage, SAN)
    4. Sign certificate with CA's private key
    5. Save private key and certificate to files
    """
    print(f"\n[*] Issuing certificate for CN='{common_name}'...")

    # Step 1: Generate entity's RSA private key
    print(f"    [*] Generating 2048-bit RSA private key...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=KEY_SIZE,
        backend=default_backend()
    )

    # Step 2: Build certificate
    print(f"    [*] Building certificate...")
    
    # Subject: The entity's identity (server or client)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, COUNTRY),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, ORGANIZATION),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    
    # Issuer: The Root CA (who signs this certificate)
    issuer = ca_cert.subject
    
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(issuer)
    builder = builder.public_key(private_key.public_key())
    builder = builder.serial_number(x509.random_serial_number())
    
    # Validity period
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = builder.not_valid_before(now)
    builder = builder.not_valid_after(now + datetime.timedelta(days=VALIDITY_DAYS))

    # Step 3: Add X.509 v3 extensions
    
    # BasicConstraints: CA=FALSE (this is an end-entity certificate)
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    )
    
    # Subject Alternative Name (SAN)
    # Modern validation requires SAN even if CN is present
    # Maps the CN to a DNS name for hostname verification
    builder = builder.add_extension(
        x509.SubjectAlternativeName([x509.DNSName(common_name)]),
        critical=False,
    )
    
    # KeyUsage: Digital Signature, Key Encipherment
    # Appropriate for TLS client/server authentication and RSA key exchange
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=True,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,      # Not a CA
            crl_sign=False,           # Not a CA
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True
    )
    
    # Extended Key Usage: Server Auth / Client Auth
    if "server" in filename_base.lower():
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
    else:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
    
    # Subject Key Identifier
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
        critical=False,
    )
    
    # Authority Key Identifier (links to CA)
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
        critical=False,
    )

    # Step 4: Sign the certificate using CA's private key
    print(f"    [*] Signing certificate with Root CA...")
    certificate = builder.sign(
        private_key=ca_key,
        algorithm=hashes.SHA256(),
        backend=default_backend()
    )

    # Step 5: Save files
    key_path = os.path.join(CERTS_DIR, f"{filename_base}.key")
    cert_path = os.path.join(CERTS_DIR, f"{filename_base}.crt")

    print(f"    [*] Saving private key to: {key_path}")
    with open(key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    print(f"    [*] Saving certificate to: {cert_path}")
    with open(cert_path, "wb") as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))
    
    print(f"    [+] Certificate for '{common_name}' generated successfully!")
    return cert_path


def main():
    """
    Main function: Issues certificates for server and client.
    """
    print("=" * 70)
    print("SecureChat Certificate Issuance")
    print("=" * 70)
    
    # Ensure output directory exists
    Path(CERTS_DIR).mkdir(parents=True, exist_ok=True)
    
    # Load Root CA
    try:
        print("[*] Loading Root CA...")
        ca_cert, ca_key = load_ca_assets()
        print("[+] Root CA loaded successfully.")
    except FileNotFoundError as e:
        print(f"\n[!] Error: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Issue Server Certificate
    generate_signed_cert(
        common_name="server",
        filename_base="server",
        ca_cert=ca_cert,
        ca_key=ca_key
    )
    
    # Issue Client Certificate
    generate_signed_cert(
        common_name="client",
        filename_base="client",
        ca_cert=ca_cert,
        ca_key=ca_key
    )
    
    print()
    print("=" * 70)
    print("[+] All certificates issued successfully!")
    print("=" * 70)
    print("\nGenerated Files:")
    print(f"  Server: certs/server.key, certs/server.crt")
    print(f"  Client: certs/client.key, certs/client.crt")
    print()
    print("Next Steps:")
    print("  1. Start the server:")
    print("     python -m app.server")
    print()
    print("  2. Start the client (in another terminal):")
    print("     python -m app.client")
    print("=" * 70)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"\n[!] Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)

