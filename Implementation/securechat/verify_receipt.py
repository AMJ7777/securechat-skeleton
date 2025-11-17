"""
Offline Receipt Verification Script

Verifies the authenticity and integrity of session transcripts and receipts.

Verification Process:
1. Load transcript log file
2. Load session receipt (JSON)
3. Load peer's certificate
4. Recompute transcript hash
5. Verify hash matches receipt
6. Verify RSA signature on receipt

Security Properties:
- Detects any tampering with transcript
- Proves receipt was signed by peer's private key
- Enables third-party verification (auditing)
- Demonstrates non-repudiation

Usage:
    python verify_receipt.py

Prerequisites:
    - client_transcript.log, server_receipt.json, certs/server.crt
    - server_transcript.log, client_receipt.json, certs/client.crt
"""

import sys
import json
import hashlib
from pathlib import Path

from app.crypto import sign, pki
from app.common.utils import b64d


def verify_receipt(transcript_path: str, receipt_path: str, cert_path: str) -> bool:
    """
    Verifies a session receipt against a transcript.
    
    Args:
        transcript_path: Path to transcript log file
        receipt_path: Path to receipt JSON file
        cert_path: Path to peer's certificate
        
    Returns:
        bool: True if verification succeeds
        
    Verification Steps:
    1. Load all files
    2. Recompute transcript hash (must match transcript.py logic)
    3. Compare with hash in receipt
    4. Verify RSA signature over hash
    """
    print(f"\n{'='*70}")
    print(f"Verifying: {receipt_path}")
    print(f"{'='*70}")
    
    try:
        # Step 1: Load files
        print(f"[*] Loading transcript: {transcript_path}")
        with open(transcript_path, 'r') as f:
            transcript_lines = f.read().splitlines()
        print(f"    Loaded {len(transcript_lines)} message(s)")
        
        print(f"[*] Loading receipt: {receipt_path}")
        with open(receipt_path, 'r') as f:
            receipt = json.load(f)
        print(f"    Peer: {receipt['peer']}")
        print(f"    Sequence range: {receipt['first_seq']} - {receipt['last_seq']}")
        
        print(f"[*] Loading certificate: {cert_path}")
        with open(cert_path, 'r') as f:
            peer_cert = pki.load_cert(f.read())
        cn = peer_cert.subject.get_attributes_for_oid(pki.NameOID.COMMON_NAME)[0].value
        print(f"    Certificate CN: {cn}")
        
        # Step 2: Recompute transcript hash
        # CRITICAL: Must match the hash computation in transcript.py
        # We concatenate all lines WITHOUT newlines (same as Transcript.compute_hash())
        print(f"[*] Recomputing transcript hash...")
        transcript_content = "".join(transcript_lines)
        computed_hash = hashlib.sha256(transcript_content.encode('utf-8')).hexdigest()
        print(f"    Computed:  {computed_hash}")
        print(f"    Expected:  {receipt['transcript_sha256']}")
        
        # Step 3: Compare hashes
        if computed_hash != receipt['transcript_sha256']:
            print(f"\n[FAIL] Transcript hash mismatch!")
            print(f"       This indicates the transcript has been tampered with.")
            return False
        
        print(f"[+] Transcript hash verified")
        
        # Step 4: Verify RSA signature
        print(f"[*] Verifying RSA signature...")
        peer_public_key = peer_cert.public_key()
        sig_bytes = b64d(receipt['sig'])
        hash_bytes = computed_hash.encode('utf-8')
        
        try:
            sign.verify(peer_public_key, sig_bytes, hash_bytes)
            print(f"[+] Signature verified")
        except Exception as e:
            print(f"\n[FAIL] Signature verification failed: {e}")
            print(f"       This indicates the receipt is forged or tampered.")
            return False
        
        # All checks passed
        print()
        print(f"{'='*70}")
        print(f"[SUCCESS] Receipt is VALID and AUTHENTIC")
        print(f"{'='*70}")
        print(f"  - Transcript integrity: CONFIRMED")
        print(f"  - Signature authenticity: CONFIRMED")
        print(f"  - Signed by: {cn}")
        print(f"  - Messages: {receipt['first_seq']} to {receipt['last_seq']}")
        print(f"{'='*70}")
        
        return True
        
    except FileNotFoundError as e:
        print(f"\n[ERROR] File not found: {e}")
        print(f"        Make sure you have run a chat session first.")
        return False
    except Exception as e:
        print(f"\n[ERROR] Verification failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """
    Main verification function.
    
    Verifies both directions:
    1. Server's receipt (against client's transcript)
    2. Client's receipt (against server's transcript)
    """
    print("=" * 70)
    print("SecureChat Receipt Verification (Offline)")
    print("=" * 70)
    print()
    print("This script demonstrates NON-REPUDIATION:")
    print("  - Verifies transcript integrity")
    print("  - Verifies cryptographic signatures")
    print("  - Can be performed by third parties (e.g., auditors)")
    print()
    
    # Check if evidence files exist
    required_files = [
        "client_transcript.log",
        "server_receipt.json",
        "server_transcript.log",
        "client_receipt.json",
        "certs/server.crt",
        "certs/client.crt"
    ]
    
    missing = [f for f in required_files if not Path(f).exists()]
    if missing:
        print("[!] Missing required files:")
        for f in missing:
            print(f"    - {f}")
        print()
        print("Run a complete chat session first:")
        print("  1. python -m app.server")
        print("  2. python -m app.client")
        print("  3. Type '/quit' to generate receipts")
        sys.exit(1)
    
    # Verify server's receipt (against client's log)
    print("\n" + "=" * 70)
    print("TEST 1: Verify Server's Receipt")
    print("=" * 70)
    result1 = verify_receipt(
        "client_transcript.log",
        "server_receipt.json",
        "certs/server.crt"
    )
    
    # Verify client's receipt (against server's log)
    print("\n" + "=" * 70)
    print("TEST 2: Verify Client's Receipt")
    print("=" * 70)
    result2 = verify_receipt(
        "server_transcript.log",
        "client_receipt.json",
        "certs/client.crt"
    )
    
    # Summary
    print("\n" + "=" * 70)
    print("VERIFICATION SUMMARY")
    print("=" * 70)
    print(f"  Server Receipt: {'✓ VALID' if result1 else '✗ INVALID'}")
    print(f"  Client Receipt: {'✓ VALID' if result2 else '✗ INVALID'}")
    print("=" * 70)
    
    if result1 and result2:
        print("\n[+] Non-repudiation demonstrated successfully!")
        print("    Both parties have cryptographic proof of the conversation.")
        print("    Neither can deny participation or alter the transcript.")
        sys.exit(0)
    else:
        print("\n[-] Verification failed. Check for tampering or errors.")
        sys.exit(1)


if __name__ == "__main__":
    main()

