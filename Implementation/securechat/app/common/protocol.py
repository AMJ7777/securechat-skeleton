"""
Protocol message definitions using Pydantic models.
Defines the structured messages exchanged during the SecureChat protocol.

Protocol Phases:
1. Control Plane: Hello, ServerHello, Register, Login
2. Key Agreement: DHClient, DHServer
3. Data Plane: Msg
4. Tear Down: Receipt
"""

from pydantic import BaseModel, Field
from typing import Literal


# ============================================================================
# PHASE 1: Control Plane (Negotiation & Authentication)
# ============================================================================

class Hello(BaseModel):
    """
    Initial client hello message containing the client's X.509 certificate.
    
    Security Properties:
    - Initiates mutual authentication
    - Includes nonce for freshness
    - Certificate binding for identity
    """
    type: Literal["hello"] = "hello"
    client_cert: str = Field(..., description="Client X.509 certificate (PEM format)")
    nonce: str = Field(..., description="Base64-encoded random nonce (16 bytes)")


class ServerHello(BaseModel):
    """
    Server response to hello, containing the server's X.509 certificate.
    
    Security Properties:
    - Completes mutual authentication
    - Server proves identity via CA-signed certificate
    """
    type: Literal["server_hello"] = "server_hello"
    server_cert: str = Field(..., description="Server X.509 certificate (PEM format)")
    nonce: str = Field(..., description="Base64-encoded random nonce (16 bytes)")


class Register(BaseModel):
    """
    User registration payload (transmitted encrypted under temporary DH key).
    
    Security Properties:
    - Never sent in plaintext
    - Password is pre-hashed client-side (salt generated server-side)
    - Encrypted using ephemeral AES key from DH exchange
    """
    type: Literal["register"] = "register"
    email: str = Field(..., description="User email address")
    username: str = Field(..., description="Unique username")
    pwd: str = Field(..., description="User password (plaintext, hashed server-side)")
    salt: str = Field(default="", description="Ignored by server (server generates own salt)")


class Login(BaseModel):
    """
    User login payload (transmitted encrypted under temporary DH key).
    
    Security Properties:
    - Credentials encrypted under ephemeral key
    - Nonce prevents replay attacks
    - Two-factor validation: certificate + password
    """
    type: Literal["login"] = "login"
    email: str = Field(..., description="Username or email identifier")
    pwd: str = Field(..., description="User password (plaintext, verified against stored hash)")
    nonce: str = Field(..., description="Base64-encoded freshness nonce")


# ============================================================================
# PHASE 2: Key Agreement (Diffie-Hellman)
# ============================================================================

class DHClient(BaseModel):
    """
    Client's Diffie-Hellman public key and parameters.
    
    Security Properties:
    - Establishes ephemeral shared secret
    - Uses safe prime (RFC 3526 Group 14)
    - Forward secrecy: unique key per session
    """
    type: Literal["dh_client"] = "dh_client"
    g: int = Field(..., description="Generator (typically 2)")
    p: int = Field(..., description="Large safe prime (2048-bit)")
    A: int = Field(..., description="Client's public key: g^a mod p")


class DHServer(BaseModel):
    """
    Server's Diffie-Hellman public key response.
    
    Security Properties:
    - Completes DH key exchange
    - Both sides can now compute shared secret Ks
    - Session key derived: K = Trunc16(SHA256(Ks))
    """
    type: Literal["dh_server"] = "dh_server"
    B: int = Field(..., description="Server's public key: g^b mod p")


# ============================================================================
# PHASE 3: Data Plane (Encrypted Chat)
# ============================================================================

class Msg(BaseModel):
    """
    Encrypted chat message with integrity and authenticity protection.
    
    Security Properties:
    - Confidentiality: AES-128 encryption
    - Integrity: SHA-256 digest of (seqno || ts || ct)
    - Authenticity: RSA signature over digest
    - Replay protection: strictly increasing seqno
    - Freshness: timestamp verification
    """
    type: Literal["msg"] = "msg"
    seqno: int = Field(..., description="Sequence number (strictly increasing)")
    ts: float = Field(..., description="Unix timestamp in milliseconds")
    ct: str = Field(..., description="Base64-encoded AES-128 ciphertext")
    sig: str = Field(..., description="Base64-encoded RSA signature over SHA256(seqno||ts||ct)")


# ============================================================================
# PHASE 4: Non-Repudiation (Tear Down)
# ============================================================================

class Receipt(BaseModel):
    """
    Session receipt for non-repudiation.
    
    Security Properties:
    - Cryptographic proof of communication
    - Transcript hash binds all messages in session
    - RSA signature prevents denial
    - Offline verifiable by third parties
    
    Exchanged at session end between client and server.
    """
    type: Literal["receipt"] = "receipt"
    peer: Literal["client", "server"] = Field(..., description="Sender identity")
    first_seq: int = Field(..., description="First sequence number in session")
    last_seq: int = Field(..., description="Last sequence number in session")
    transcript_sha256: str = Field(..., description="SHA-256 hash of complete transcript (hex)")
    sig: str = Field(..., description="Base64-encoded RSA signature over transcript_sha256")

