"""
Public Key Infrastructure (PKI) Module

Handles X.509 certificate operations:
- Certificate loading and parsing
- Certificate chain validation
- Expiry checking
- Common Name (CN) verification

Security Properties:
- Mutual authentication via CA-signed certificates
- Prevents self-signed, expired, or untrusted certificates
- Identity binding through CN validation
"""

import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID


def load_cert(pem_data: str | bytes) -> x509.Certificate:
    """
    Loads and parses a PEM-encoded X.509 certificate.
    
    Args:
        pem_data: Certificate in PEM format (string or bytes)
        
    Returns:
        x509.Certificate: Parsed certificate object
        
    Raises:
        ValueError: If PEM data is malformed
    """
    if isinstance(pem_data, str):
        pem_bytes = pem_data.encode('utf-8')
    else:
        pem_bytes = pem_data
    
    return x509.load_pem_x509_certificate(pem_bytes, default_backend())


def load_private_key(pem_bytes: bytes, password: bytes = None):
    """
    Loads a PEM-encoded RSA private key.
    
    Args:
        pem_bytes: Private key in PEM format
        password: Optional password for encrypted keys (None for this assignment)
        
    Returns:
        RSAPrivateKey: Loaded private key object
        
    Security Note:
        In production, private keys should be password-protected.
        For this assignment, keys are stored unencrypted for simplicity.
    """
    return serialization.load_pem_private_key(
        pem_bytes,
        password=password,
        backend=default_backend()
    )


def verify_cert(
    peer_cert_pem: str,
    ca_cert_pem: str,
    expected_cn: str = None
) -> x509.Certificate:
    """
    Validates a peer certificate against the trusted Root CA.
    
    Validation Steps:
    1. Verify signature chain (certificate signed by CA)
    2. Verify validity period (not expired, not yet valid)
    3. Verify Common Name (identity match)
    
    Args:
        peer_cert_pem: Peer's certificate (PEM format)
        ca_cert_pem: Root CA certificate (PEM format)
        expected_cn: Expected Common Name (None skips CN check)
        
    Returns:
        x509.Certificate: Validated certificate object
        
    Raises:
        ValueError: With "BAD_CERT" prefix if validation fails
        
    Security Properties:
    - Rejects self-signed certificates
    - Rejects expired or not-yet-valid certificates
    - Prevents identity spoofing via CN mismatch
    - Uses cryptographic signature verification
    """
    peer_cert = load_cert(peer_cert_pem)
    ca_cert = load_cert(ca_cert_pem)

    # ========================================================================
    # CHECK 1: Verify Signature Chain (Trust)
    # ========================================================================
    # The peer certificate must be signed by the trusted Root CA.
    # This prevents accepting forged or self-signed certificates.
    
    ca_public_key = ca_cert.public_key()
    try:
        ca_public_key.verify(
            peer_cert.signature,
            peer_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            peer_cert.signature_hash_algorithm,
        )
    except Exception as e:
        raise ValueError(
            f"BAD_CERT: Certificate signature verification failed. "
            f"Not signed by trusted CA. Details: {e}"
        )

    # ========================================================================
    # CHECK 2: Verify Validity Period (Expiry)
    # ========================================================================
    # Reject certificates that are expired or not yet valid.
    
    now = datetime.datetime.now(datetime.timezone.utc)
    
    if now < peer_cert.not_valid_before_utc:
        raise ValueError(
            f"BAD_CERT: Certificate is not yet valid. "
            f"Valid from: {peer_cert.not_valid_before_utc}"
        )
    
    if now > peer_cert.not_valid_after_utc:
        raise ValueError(
            f"BAD_CERT: Certificate has expired. "
            f"Valid until: {peer_cert.not_valid_after_utc}"
        )

    # ========================================================================
    # CHECK 3: Verify Common Name (Identity)
    # ========================================================================
    # Ensure the certificate belongs to the expected entity.
    # This prevents accepting valid certificates issued to different entities.
    
    if expected_cn:
        try:
            cn_attributes = peer_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            if not cn_attributes:
                raise ValueError("BAD_CERT: Certificate has no Common Name (CN).")
            
            actual_cn = cn_attributes[0].value
            
            if actual_cn != expected_cn:
                raise ValueError(
                    f"BAD_CERT: Common Name mismatch. "
                    f"Expected '{expected_cn}', got '{actual_cn}'."
                )
        except ValueError:
            # Re-raise ValueError (our BAD_CERT errors)
            raise
        except Exception as e:
            raise ValueError(f"BAD_CERT: Failed to verify identity: {e}")

    # All checks passed: certificate is valid and trusted
    return peer_cert


def get_cert_fingerprint(cert: x509.Certificate) -> str:
    """
    Computes the SHA-256 fingerprint of a certificate.
    
    Used for:
    - Transcript logging (binds messages to certificate)
    - Certificate pinning
    - Identity verification
    
    Args:
        cert: Certificate object
        
    Returns:
        str: Hex-encoded SHA-256 fingerprint (64 characters)
    """
    from cryptography.hazmat.primitives import hashes
    return cert.fingerprint(hashes.SHA256()).hex()

