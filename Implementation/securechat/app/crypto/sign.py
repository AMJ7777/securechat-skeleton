"""
Digital Signature Module (RSA with SHA-256)

Provides message signing and verification using RSA.

Security Properties:
- Authenticity: Proves message originated from private key holder
- Integrity: Detects any modification to signed data
- Non-repudiation: Signer cannot deny creating signature

Algorithm: RSASSA-PKCS1-v1_5 with SHA-256
- Industry standard padding scheme
- Deterministic (same message + key = same signature)
- Secure against known attacks when using SHA-256

Usage in Protocol:
1. Per-message signatures: Sign SHA256(seqno || ts || ct)
2. Transcript receipts: Sign SHA256(transcript)
"""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature


def sign(private_key: rsa.RSAPrivateKey, data: bytes) -> bytes:
    """
    Computes an RSA digital signature over the provided data.
    
    Process:
    1. Hash data with SHA-256
    2. Encrypt hash with private key (signing)
    3. Apply PKCS#1 v1.5 padding
    
    Args:
        private_key: Signer's RSA private key (from certificate)
        data: Raw bytes to sign (e.g., message digest)
        
    Returns:
        bytes: Digital signature (256 bytes for 2048-bit RSA)
        
    Security Notes:
        - Only the private key holder can produce valid signatures
        - Signature is deterministic (helps with testing)
        - PKCS#1 v1.5 is secure when used with SHA-256
        
    Example:
        # Sign a message digest
        digest = f"{seqno}{timestamp}{ciphertext}".encode()
        signature = sign(my_private_key, digest)
    """
    signature = private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return signature


def verify(public_key: rsa.RSAPublicKey, signature: bytes, data: bytes) -> None:
    """
    Verifies an RSA digital signature.
    
    Process:
    1. Decrypt signature with public key
    2. Hash provided data with SHA-256
    3. Compare decrypted hash with computed hash
    
    Args:
        public_key: Signer's RSA public key (from their certificate)
        signature: The received signature bytes
        data: Original data that was signed
        
    Raises:
        InvalidSignature: If signature verification fails
        
    Security Properties:
        - Detects any modification to 'data'
        - Detects forged signatures
        - Detects signature from wrong key
        
    Usage:
        try:
            verify(peer_public_key, signature, original_data)
            print("Signature valid: message authenticated")
        except InvalidSignature:
            print("Security Alert: Signature verification failed!")
            # Drop message, log security event
    """
    try:
        public_key.verify(
            signature,
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
    except InvalidSignature:
        # Re-raise with clear error message
        raise InvalidSignature(
            "Digital signature verification failed. "
            "Message may be forged, tampered, or from wrong sender."
        )

