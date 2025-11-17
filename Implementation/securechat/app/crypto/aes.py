"""
AES-128 Encryption Module (ECB Mode with PKCS#7 Padding)

Note: ECB mode is used per assignment specification. In production, 
CBC or GCM modes should be used for semantic security.

Security Properties:
- Confidentiality via AES-128
- PKCS#7 padding for block alignment
- Key derivation from DH shared secret
"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend


def encrypt(key: bytes, plaintext: bytes) -> bytes:
    """
    Encrypts plaintext using AES-128 in ECB mode with PKCS#7 padding.
    
    Args:
        key: 16-byte AES-128 key (derived from DH shared secret)
        plaintext: Raw bytes to encrypt
        
    Returns:
        bytes: Encrypted ciphertext (length = ceil(len(plaintext) / 16) * 16)
        
    Raises:
        ValueError: If key length is not exactly 16 bytes
        
    Security Note:
        ECB mode does not hide patterns in plaintext. Used here only
        because the assignment explicitly requires "AES-128 (block cipher)".
        In real systems, use CBC, CTR, or GCM modes.
    """
    if len(key) != 16:
        raise ValueError("AES-128 requires exactly 16 bytes (128 bits) key.")

    # Step 1: Apply PKCS#7 padding to plaintext
    # Padding ensures plaintext length is a multiple of 128 bits (16 bytes)
    padder = padding.PKCS7(128).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    # Step 2: Encrypt using AES-128 in ECB mode
    cipher = Cipher(
        algorithms.AES(key),
        modes.ECB(),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    return ciphertext


def decrypt(key: bytes, ciphertext: bytes) -> bytes:
    """
    Decrypts ciphertext using AES-128 in ECB mode and removes PKCS#7 padding.
    
    Args:
        key: 16-byte AES-128 key (same key used for encryption)
        ciphertext: Raw encrypted bytes
        
    Returns:
        bytes: Original plaintext
        
    Raises:
        ValueError: If key length is incorrect or padding is invalid
        
    Security Note:
        Invalid padding indicates either:
        1. Wrong decryption key
        2. Corrupted or tampered ciphertext
        3. Active attack attempt
    """
    if len(key) != 16:
        raise ValueError("AES-128 requires exactly 16 bytes (128 bits) key.")

    # Step 1: Decrypt using AES-128 in ECB mode
    cipher = Cipher(
        algorithms.AES(key),
        modes.ECB(),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Step 2: Remove PKCS#7 padding
    unpadder = padding.PKCS7(128).unpadder()
    try:
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        return plaintext
    except ValueError as e:
        raise ValueError(f"Decryption failed: Invalid padding or incorrect key. {e}")

