"""
Root Certificate Authority (CA) Generation Script

Creates a self-signed Root CA certificate and private key.
This CA will be used to sign and issue certificates for the server and clients.

Security Properties:
- 2048-bit RSA key (secure against current attacks)
- Self-signed (issuer = subject)
- BasicConstraints: CA=TRUE (enables certificate signing)
- 1-year validity period
- SHA-256 signature algorithm

Output:
    certs/ca.key - Root CA private key (KEEP SECRET!)
    certs/ca.crt - Root CA certificate (distribute to all parties)

Usage:
    python scripts/gen_ca.py
    
IMPORTANT: The ca.key file must be kept secure and never committed to version control.
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
KEY_SIZE = 2048              # RSA key size (bits)
VALIDITY_DAYS = 365          # Certificate validity period
CERTS_DIR = "certs"          # Output directory
CA_COUNTRY = "PK"            # Pakistan
CA_ORGANIZATION = "FAST-NUCES SecureChat"
CA_COMMON_NAME = "SecureChat Root CA"


def generate_root_ca():
    """
    Generates a self-signed Root CA certificate and private key.
    
    Steps:
    1. Create output directory if it doesn't exist
    2. Generate RSA private key (2048-bit)
    3. Build self-signed certificate (issuer = subject)
    4. Add CA extensions (BasicConstraints, KeyUsage)
    5. Sign certificate with private key
    6. Save private key and certificate to files
    """
    print("=" * 70)
    print("SecureChat Root Certificate Authority Generator")
    print("=" * 70)
    print(f"[*] Generating Root CA in '{CERTS_DIR}/' directory...")
    
    # Step 1: Ensure output directory exists
    Path(CERTS_DIR).mkdir(parents=True, exist_ok=True)

    # Step 2: Generate RSA private key (2048-bit)
    print("[*] Generating 2048-bit RSA private key...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,      # Standard RSA public exponent
        key_size=KEY_SIZE,
        backend=default_backend()
    )

    # Step 3: Build certificate
    # For a Root CA, the issuer and subject are identical (self-signed)
    print("[*] Building self-signed certificate...")
    
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, CA_COUNTRY),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, CA_ORGANIZATION),
        x509.NameAttribute(NameOID.COMMON_NAME, CA_COMMON_NAME),
    ])

    # Certificate builder
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(issuer)
    builder = builder.public_key(private_key.public_key())
    builder = builder.serial_number(x509.random_serial_number())
    
    # Validity period
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = builder.not_valid_before(now)
    builder = builder.not_valid_after(now + datetime.timedelta(days=VALIDITY_DAYS))

    # Step 4: Add X.509 v3 extensions
    
    # BasicConstraints: CA=TRUE (critical)
    # This extension marks the certificate as a Certificate Authority,
    # allowing it to sign other certificates.
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True,
    )
    
    # KeyUsage: Certificate Signing, CRL Signing (critical)
    # Defines what the certificate can be used for.
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,      # Required for CA
            crl_sign=True,           # Required for CA
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )
    
    # Subject Key Identifier (recommended for CAs)
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
        critical=False,
    )

    # Step 5: Sign the certificate with the private key (self-signed)
    print("[*] Signing certificate...")
    certificate = builder.sign(
        private_key=private_key,
        algorithm=hashes.SHA256(),
        backend=default_backend()
    )

    # Step 6: Save private key to file
    key_path = os.path.join(CERTS_DIR, "ca.key")
    print(f"[*] Saving private key to: {key_path}")
    with open(key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),  # No password protection
        ))

    # Step 7: Save certificate to file
    cert_path = os.path.join(CERTS_DIR, "ca.crt")
    print(f"[*] Saving certificate to: {cert_path}")
    with open(cert_path, "wb") as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))

    print()
    print("=" * 70)
    print("[+] Root CA generated successfully!")
    print("=" * 70)
    print(f"    Private Key:  {key_path}  [KEEP SECRET!]")
    print(f"    Certificate:  {cert_path}  [Distribute to all parties]")
    print()
    print("Certificate Details:")
    print(f"    Subject:      {CA_COMMON_NAME}")
    print(f"    Issuer:       {CA_COMMON_NAME} (self-signed)")
    print(f"    Serial:       {certificate.serial_number}")
    print(f"    Valid From:   {certificate.not_valid_before_utc}")
    print(f"    Valid Until:  {certificate.not_valid_after_utc}")
    print(f"    Key Size:     {KEY_SIZE} bits")
    print("=" * 70)
    print()
    print("Next Steps:")
    print("  1. Generate server and client certificates:")
    print("     python scripts/gen_cert.py")
    print()
    print("  2. Add 'certs/' to .gitignore (if not already done)")
    print()
    print("WARNING: Never commit ca.key to version control!")
    print("=" * 70)


if __name__ == "__main__":
    try:
        generate_root_ca()
    except Exception as e:
        print(f"\n[!] Error: {e}", file=sys.stderr)
        sys.exit(1)

