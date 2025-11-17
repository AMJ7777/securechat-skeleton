"""
Common utility functions for the SecureChat protocol.
Provides time, encoding, and hashing helpers used throughout the system.
"""

import time
import base64
import hashlib


def now_ms() -> float:
    """
    Returns the current Unix timestamp in milliseconds.
    
    Used for:
    - Message timestamps (replay protection)
    - Freshness verification
    - Session timing
    
    Returns:
        float: Current time in milliseconds since epoch
    """
    return time.time() * 1000


def b64e(data: bytes) -> str:
    """
    Base64 encodes bytes to a string for JSON transport.
    
    Used for:
    - Nonces
    - Salts
    - Ciphertext
    - Digital signatures
    
    Args:
        data: Raw bytes to encode
        
    Returns:
        str: Base64-encoded string (ASCII-safe)
    """
    return base64.b64encode(data).decode('ascii')


def b64d(encoded_str: str) -> bytes:
    """
    Base64 decodes a string back to bytes.
    
    Args:
        encoded_str: Base64-encoded string
        
    Returns:
        bytes: Decoded raw bytes
        
    Raises:
        ValueError: If the input is not valid Base64
    """
    return base64.b64decode(encoded_str)


def sha256_hex(data: bytes) -> str:
    """
    Computes the SHA-256 hash and returns the hexadecimal digest.
    
    Used for:
    - Password hashing (salted)
    - Transcript hash computation
    - Message integrity verification
    
    Args:
        data: Raw bytes to hash
        
    Returns:
        str: Hex string (64 characters, lowercase)
    """
    return hashlib.sha256(data).hexdigest()


def sha256_bytes(data: bytes) -> bytes:
    """
    Computes the SHA-256 hash and returns raw bytes.
    
    Args:
        data: Raw bytes to hash
        
    Returns:
        bytes: 32-byte digest
    """
    return hashlib.sha256(data).digest()

