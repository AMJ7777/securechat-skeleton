"""
Transcript Module for Non-Repudiation

Maintains an append-only log of all messages in a session.
Used to create cryptographic proof of communication.

Security Properties:
- Append-only: No message can be removed or modified
- Certificate binding: Each message tied to sender's certificate
- Hash chaining: Final transcript hash covers all messages
- Signature-protected: Transcript hash is signed for non-repudiation

Transcript Format:
    seqno | timestamp | ciphertext | signature | cert_fingerprint
    
Example Entry:
    0|1699999123456.789|YWJjZGVm...|bXl4eXo...|a1b2c3d4e5f6...

Usage:
    1. During chat: Add each sent/received message
    2. At session end: Compute hash of entire transcript
    3. Sign hash to create SessionReceipt
    4. Export transcript and receipt for offline verification
"""

import hashlib
from cryptography import x509
from cryptography.hazmat.primitives import hashes


class Transcript:
    """
    In-memory append-only transcript for session logging.
    
    Attributes:
        _lines: List of transcript entries (never modified after append)
    """
    
    def __init__(self):
        """
        Initializes an empty transcript.
        Each session gets a fresh transcript instance.
        """
        self._lines = []

    def add(
        self,
        seqno: int,
        ts: float,
        ct: str,
        sig: str,
        peer_cert: x509.Certificate
    ):
        """
        Appends a message entry to the transcript.
        
        Format: seqno|timestamp|ciphertext|signature|cert_fingerprint
        
        Args:
            seqno: Message sequence number (strictly increasing)
            ts: Unix timestamp in milliseconds
            ct: Base64-encoded ciphertext
            sig: Base64-encoded RSA signature
            peer_cert: Sender's X.509 certificate
            
        Security Notes:
            - Certificate fingerprint binds message to sender identity
            - Pipe-delimited format for easy parsing
            - Each field is tamper-evident (included in final hash)
            - Order is preserved (sequence numbers)
        """
        # Compute certificate fingerprint (SHA-256 of DER-encoded cert)
        # This uniquely identifies the sender's certificate
        fingerprint = peer_cert.fingerprint(hashes.SHA256()).hex()

        # Format transcript line
        # Delimiter: | (pipe character)
        # Fields: seqno, timestamp, ciphertext, signature, cert_fingerprint
        line = f"{seqno}|{ts}|{ct}|{sig}|{fingerprint}"
        
        # Append to transcript (immutable after addition)
        self._lines.append(line)

    def compute_hash(self) -> str:
        """
        Computes the SHA-256 hash of the complete transcript.
        
        Process:
        1. Concatenate all transcript lines (no separators)
        2. Hash the concatenated string with SHA-256
        3. Return hex digest
        
        Returns:
            str: Hex-encoded SHA-256 hash (64 characters)
            
        Security Properties:
            - Any modification to any message changes the hash
            - Any deletion of a message changes the hash
            - Any reordering of messages changes the hash
            - Hash serves as a cryptographic commitment to the session
            
        Usage:
            At session end, both parties:
            1. Compute transcript hash
            2. Sign the hash with their private key
            3. Exchange signed receipts
            4. Store receipts for non-repudiation
        """
        # Concatenate all lines into a single string (NO newlines)
        # This matches the verification logic in verify_receipt.py
        full_transcript = "".join(self._lines)
        
        # Compute SHA-256 hash
        digest_bytes = hashlib.sha256(full_transcript.encode('utf-8')).digest()
        
        # Return as hexadecimal string
        return digest_bytes.hex()

    def export(self) -> str:
        """
        Exports the transcript as a newline-separated string.
        
        Returns:
            str: Complete transcript with each entry on a new line
            
        Usage:
            Save to file for offline verification:
            
            with open("client_transcript.log", "w") as f:
                f.write(transcript.export())
                
        Format:
            Each line: seqno|timestamp|ciphertext|signature|cert_fingerprint
            
        Security Note:
            The exported file should be treated as evidence.
            Changing any character will invalidate the SessionReceipt signature.
        """
        return "\n".join(self._lines)

    def __len__(self):
        """
        Returns the number of messages in the transcript.
        
        Returns:
            int: Message count
        """
        return len(self._lines)

    def __str__(self):
        """
        String representation for debugging.
        
        Returns:
            str: Summary of transcript state
        """
        return f"<Transcript: {len(self._lines)} messages>"

