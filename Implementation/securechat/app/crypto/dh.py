"""
Diffie-Hellman Key Exchange Module

Implements classical DH key agreement using RFC 3526 Group 14 (2048-bit MODP).

Security Properties:
- Forward secrecy: unique session key per connection
- Passive eavesdropping resistance
- Uses cryptographically strong safe prime
- Session key derivation via SHA-256

Protocol Flow:
1. Client generates private 'a', computes A = g^a mod p
2. Server generates private 'b', computes B = g^b mod p
3. Both compute shared secret: Ks = B^a mod p = A^b mod p
4. Session key derived: K = Trunc16(SHA256(big-endian(Ks)))
"""

import secrets
import hashlib


# RFC 3526 - 2048-bit MODP Group (Group 14)
# This is a well-known, standardized safe prime approved for cryptographic use.
# Using standard groups prevents weak parameter attacks.
RFC_3526_PRIME_2048_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF"
)

DEFAULT_PRIME = int(RFC_3526_PRIME_2048_HEX, 16)
DEFAULT_GENERATOR = 2


class DiffieHellman:
    """
    Diffie-Hellman key exchange implementation.
    
    Attributes:
        p: Large safe prime modulus
        g: Generator (typically 2)
        private_key: Secret exponent (a or b)
        public_key: Public value (A = g^a mod p or B = g^b mod p)
    """
    
    def __init__(self, p: int = None, g: int = None):
        """
        Initializes a new DH instance with public parameters.
        
        Args:
            p: Prime modulus (defaults to RFC 3526 Group 14)
            g: Generator (defaults to 2)
            
        Security Notes:
            - Private key chosen uniformly from [1, p-2]
            - Public key computed as g^(private_key) mod p
            - Using standard groups prevents small subgroup attacks
        """
        self.p = p if p is not None else DEFAULT_PRIME
        self.g = g if g is not None else DEFAULT_GENERATOR
        
        # Generate cryptographically secure random private key
        # Must satisfy: 1 < private_key < p-1
        self.private_key = secrets.randbelow(self.p - 2) + 1
        
        # Compute public key: g^private_key mod p
        self.public_key = pow(self.g, self.private_key, self.p)

    def compute_secret(self, peer_public_key: int) -> int:
        """
        Computes the shared secret from the peer's public key.
        
        Args:
            peer_public_key: The other party's public DH value
            
        Returns:
            int: Shared secret Ks = peer_public^private mod p
            
        Raises:
            ValueError: If peer public key is outside valid range [2, p-2]
            
        Security Notes:
            - Validates peer public key to prevent small subgroup attacks
            - Both parties compute the same shared secret without transmitting it
            - Ks should never be used directly; derive session key via KDF
        """
        # Validate peer public key to prevent trivial/small subgroup attacks
        if not (1 < peer_public_key < self.p - 1):
            raise ValueError(
                "Invalid peer public key: must be in range (1, p-1). "
                "Possible attack detected."
            )
        
        # Compute shared secret: (peer_public)^private mod p
        shared_secret = pow(peer_public_key, self.private_key, self.p)
        
        return shared_secret

    @staticmethod
    def derive_session_key(shared_secret_int: int) -> bytes:
        """
        Derives a 16-byte AES-128 session key from the DH shared secret.
        
        Key Derivation Function (KDF):
            K = Trunc16(SHA256(big-endian(Ks)))
        
        Args:
            shared_secret_int: The integer shared secret computed via DH
            
        Returns:
            bytes: 16-byte AES-128 session key
            
        Security Notes:
            - SHA-256 provides uniform distribution
            - Big-endian encoding ensures interoperability
            - Truncation to 16 bytes matches AES-128 key size
            - One-way function prevents shared secret recovery from key
        """
        # Step 1: Convert integer shared secret to big-endian bytes
        num_bytes = (shared_secret_int.bit_length() + 7) // 8
        if num_bytes == 0:  # Handle edge case (shared_secret = 0, unlikely but safe)
            num_bytes = 1
        
        shared_secret_bytes = shared_secret_int.to_bytes(num_bytes, byteorder='big')
        
        # Step 2: Hash using SHA-256
        digest = hashlib.sha256(shared_secret_bytes).digest()
        
        # Step 3: Truncate to 16 bytes (128 bits) for AES-128
        session_key = digest[:16]
        
        return session_key

