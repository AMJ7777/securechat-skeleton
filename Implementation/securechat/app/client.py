"""
SecureChat Client

Implements the client side of the secure chat protocol.

Protocol Phases:
1. Connect: Establish TCP connection
2. Handshake: Send certificate, verify server certificate
3. Auth: Register or login with encrypted credentials
4. Session: Establish unique session key via DH
5. Chat: Send/receive encrypted messages
6. Teardown: Exchange non-repudiation receipts

Security Properties:
- Server authentication via PKI
- Credential confidentiality via ephemeral DH
- Message confidentiality via AES-128
- Message authenticity via RSA signatures
- Replay protection via sequence numbers
- Non-repudiation via signed transcripts

Usage:
    python -m app.client
"""

import socket
import threading
import json
import sys
import os
import secrets

from app.common.protocol import Hello, Register, Login, DHClient, Msg, Receipt
from app.common.utils import now_ms, b64e, b64d
from app.crypto import pki, aes, dh, sign
from app.storage.transcript import Transcript


# Client Configuration
SERVER_HOST = os.getenv('SERVER_HOST', '127.0.0.1')
SERVER_PORT = int(os.getenv('SERVER_PORT', 8080))
CERTS_DIR = "certs"


class SecureChatClient:
    """
    SecureChat client implementation.
    
    State Variables:
        - sock: TCP socket connection to server
        - username: Authenticated username
        - session_key: AES-128 key for message encryption
        - seq_out: Outgoing message sequence number
        - seq_in: Expected incoming sequence number
        - transcript: Append-only message log
        - server_cert: Verified server certificate
    """
    
    def __init__(self):
        """
        Initializes the client and loads PKI assets.
        
        Raises:
            SystemExit: If certificates are missing
        """
        self.sock = None
        self.running = True
        
        # State
        self.username = None
        self.session_key = None
        self.seq_out = 0
        self.seq_in = 0
        self.transcript = Transcript()
        self.server_cert = None
        
        # Load Client PKI Assets
        try:
            with open(f"{CERTS_DIR}/client.crt", "r") as f:
                self.cert_pem = f.read()
            with open(f"{CERTS_DIR}/ca.crt", "r") as f:
                self.ca_cert_pem = f.read()
            with open(f"{CERTS_DIR}/client.key", "rb") as f:
                self.priv_key = pki.load_private_key(f.read())
        except FileNotFoundError:
            print(f"[!] Error: Missing certificates in {CERTS_DIR}/")
            print(f"    Run: python scripts/gen_ca.py")
            print(f"         python scripts/gen_cert.py")
            sys.exit(1)

    def connect(self):
        """
        Establishes TCP connection and performs PKI handshake.
        
        Steps:
        1. Connect to server
        2. Send client hello with certificate
        3. Receive server hello
        4. Verify server certificate
        
        Raises:
            ValueError: If server certificate is invalid
        """
        print("=" * 70)
        print("SecureChat Client (Assignment #2)")
        print("=" * 70)
        print()
        print(f"[*] Connecting to {SERVER_HOST}:{SERVER_PORT}...")
        
        # Establish TCP connection
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((SERVER_HOST, SERVER_PORT))
        print("[+] Connected")

        # Send client hello
        print("[*] Performing PKI handshake...")
        nonce = b64e(secrets.token_bytes(16))
        hello = Hello(client_cert=self.cert_pem, nonce=nonce)
        self.send_json(hello.model_dump())

        # Receive server hello
        resp = self.recv_json()
        if not resp or resp.get("type") != "server_hello":
            raise ValueError("Protocol error: Expected server_hello")
        
        # Verify server certificate
        print("[*] Verifying server certificate...")
        self.server_cert = pki.verify_cert(
            resp["server_cert"],
            self.ca_cert_pem,
            expected_cn="server"  # Validate server identity
        )
        print("[+] Server authenticated via PKI")
        print()

    def perform_dh_exchange(self) -> bytes:
        """
        Executes Diffie-Hellman key agreement.
        
        Steps:
        1. Generate ephemeral DH keypair
        2. Send public key (A, p, g) to server
        3. Receive server's public key (B)
        4. Compute shared secret and derive AES key
        
        Returns:
            bytes: 16-byte AES-128 session key
            
        Security:
            - Uses RFC 3526 Group 14 (2048-bit safe prime)
            - Forward secrecy: unique key per exchange
            - Key derivation: K = Trunc16(SHA256(Ks))
        """
        # Generate ephemeral DH parameters
        dh_eng = dh.DiffieHellman()  # Uses default Group 14
        
        # Send public key to server
        msg = DHClient(g=dh_eng.g, p=dh_eng.p, A=dh_eng.public_key)
        self.send_json(msg.model_dump())
        
        # Receive server's public key
        resp = self.recv_json()
        if not resp or resp.get("type") != "dh_server":
            raise ValueError("Protocol error: Expected dh_server")
        
        # Compute shared secret and derive session key
        shared_secret = dh_eng.compute_secret(resp["B"])
        key = dh.DiffieHellman.derive_session_key(shared_secret)
        
        return key

    def authenticate(self) -> bool:
        """
        Performs encrypted authentication (registration or login).
        
        Steps:
        1. Establish temporary DH encryption key
        2. Prompt user for credentials
        3. Encrypt credentials under temporary key
        4. Send to server
        5. Wait for success/failure response
        
        Returns:
            bool: True if authentication succeeds
            
        Security:
            - Credentials never sent in plaintext
            - Separate encryption key for auth (not reused for chat)
            - Server-side salted hashing
        """
        print("=" * 70)
        print("AUTHENTICATION")
        print("=" * 70)
        
        # Step 1: Establish temporary encryption key
        print("[*] Negotiating ephemeral encryption key...")
        temp_key = self.perform_dh_exchange()
        print("[+] Ephemeral key established")
        print()
        
        # Step 2: Prompt for credentials
        while True:
            print("1. Register new account")
            print("2. Login with existing account")
            choice = input("Select (1 or 2): ").strip()
            print()
            
            if choice not in ['1', '2']:
                print("[-] Invalid choice. Try again.\n")
                continue
            
            if choice == '1':
                # Registration
                print("=== Registration ===")
                email = input("Email: ").strip()
                username = input("Username: ").strip()
                password = input("Password: ").strip()
                print()
                
                if not email or not username or not password:
                    print("[-] All fields required.\n")
                    continue
                
                # Create registration payload
                payload = Register(
                    email=email,
                    username=username,
                    pwd=password,
                    salt=""  # Server generates salt
                ).model_dump_json()
                
            else:
                # Login
                print("=== Login ===")
                identifier = input("Email or Username: ").strip()
                password = input("Password: ").strip()
                print()
                
                if not identifier or not password:
                    print("[-] All fields required.\n")
                    continue
                
                # Create login payload
                payload = Login(
                    email=identifier,
                    pwd=password,
                    nonce=b64e(secrets.token_bytes(8))
                ).model_dump_json()
            
            # Step 3: Encrypt credentials
            ct_bytes = aes.encrypt(temp_key, payload.encode('utf-8'))
            
            wrapper = {
                "type": "encrypted_auth",
                "ct": b64e(ct_bytes)
            }
            
            # Step 4: Send to server
            print("[*] Sending encrypted credentials...")
            self.send_json(wrapper)
            
            # Step 5: Wait for response
            resp = self.recv_json()
            if not resp:
                print("[-] Connection lost\n")
                return False
            
            if resp.get("status") == "OK":
                print(f"[+] {resp.get('msg')}")
                self.username = username if choice == '1' else identifier
                print()
                return True
            else:
                print(f"[-] {resp.get('msg')}\n")
                # Loop back and try again

    def chat_session(self):
        """
        Main chat session after successful authentication.
        
        Steps:
        1. Establish fresh session key via DH
        2. Start receive thread for incoming messages
        3. Handle user input and send messages
        4. Cleanup on exit
        
        Security:
            - Unique session key (forward secrecy)
            - All messages encrypted and signed
            - Sequence numbers prevent replay
        """
        # Step 1: Establish session key
        print("=" * 70)
        print("SESSION SETUP")
        print("=" * 70)
        print("[*] Negotiating session key (forward secrecy)...")
        self.session_key = self.perform_dh_exchange()
        print("[+] Secure session established")
        print()
        
        # Step 2: Start receive thread
        print("=" * 70)
        print(f"SECURE CHAT (logged in as: {self.username})")
        print("=" * 70)
        print("Type your messages and press Enter.")
        print("Type '/quit' to end session and generate receipts.")
        print("=" * 70)
        print()
        
        t = threading.Thread(target=self.receive_loop, daemon=False)
        t.start()

        # Step 3: Send loop (main thread)
        self.send_loop()
        
        # Step 4: Cleanup
        t.join(timeout=2.0)

    def send_loop(self):
        """
        Handles user input, encryption, signing, and sending.
        
        Message Construction:
        1. Read user input
        2. Assign sequence number and timestamp
        3. Encrypt with AES-128
        4. Sign SHA256(seqno || ts || ct) with RSA
        5. Send message
        6. Log to transcript
        """
        while self.running:
            try:
                text = input("You: ")
                
                if not text:
                    continue
                
                if text == "/quit":
                    self.running = False
                    break

                # Prepare message
                seq = self.seq_out
                self.seq_out += 1
                ts = now_ms()
                
                # Encrypt
                ct_bytes = aes.encrypt(self.session_key, text.encode('utf-8'))
                ct_str = b64e(ct_bytes)
                
                # Sign
                raw_data = f"{seq}{ts}{ct_str}".encode('utf-8')
                sig_bytes = sign.sign(self.priv_key, raw_data)
                
                # Construct message
                msg = Msg(
                    seqno=seq,
                    ts=ts,
                    ct=ct_str,
                    sig=b64e(sig_bytes)
                )
                
                # Log to transcript
                my_cert = pki.load_cert(self.cert_pem)
                self.transcript.add(seq, ts, ct_str, b64e(sig_bytes), my_cert)
                
                # Send
                self.send_json(msg.model_dump())
                
            except EOFError:
                self.running = False
                break
            except OSError as e:
                print(f"\n[-] Connection lost: {e}")
                self.running = False
                break

    def receive_loop(self):
        """
        Handles receiving and processing incoming messages.
        
        Security Checks:
        1. Sequence number validation (replay protection)
        2. Signature verification (authenticity)
        3. Decryption (confidentiality)
        4. Transcript logging (non-repudiation)
        """
        while self.running:
            try:
                data = self.recv_json()
                if not data:
                    print("\n[-] Server disconnected")
                    self.running = False
                    break
                
                msg_type = data.get("type")
                
                # Handle session receipt
                if msg_type == "receipt":
                    self.handle_receipt(data)
                    self.running = False
                    return

                # Handle chat message
                if msg_type == "msg":
                    seq = data['seqno']
                    ts = data['ts']
                    ct = data['ct']
                    sig = data['sig']
                    
                    # Check 1: Replay protection
                    if seq < self.seq_in:
                        print(f"\n[!] SECURITY ALERT: Replay detected (seq {seq} < {self.seq_in})")
                        continue
                    self.seq_in = seq + 1
                    
                    # Check 2: Verify signature
                    raw_data = f"{seq}{ts}{ct}".encode('utf-8')
                    try:
                        server_pub = self.server_cert.public_key()
                        sign.verify(server_pub, b64d(sig), raw_data)
                    except Exception as e:
                        print(f"\n[!] SECURITY ALERT: Signature verification failed: {e}")
                        continue

                    # Check 3: Decrypt
                    try:
                        pt_bytes = aes.decrypt(self.session_key, b64d(ct))
                        message_text = pt_bytes.decode('utf-8')
                        print(f"\rServer: {message_text}")
                        print("You: ", end="", flush=True)
                    except Exception as e:
                        print(f"\n[!] Decryption failed: {e}")
                        continue
                    
                    # Check 4: Log to transcript
                    self.transcript.add(seq, ts, ct, sig, self.server_cert)

            except socket.error as e:
                print(f"\n[-] Connection error: {e}")
                self.running = False
                break
            except json.JSONDecodeError:
                print("\n[-] Invalid data from server")
                self.running = False
                break

    def handle_receipt(self, data: dict):
        """
        Handles incoming server receipt.
        
        Args:
            data: Server's session receipt
        """
        print("\n[*] Received session receipt from server")
        
        # Save server's receipt
        with open("server_receipt.json", "w") as f:
            json.dump(data, f, indent=2)
        print("[+] Server receipt saved to server_receipt.json")

    def perform_shutdown(self):
        """
        Generates and sends session receipt for non-repudiation.
        
        Steps:
        1. Compute transcript hash
        2. Sign hash with client's private key
        3. Send receipt to server
        4. Save transcript and receipt locally
        
        Creates cryptographic proof of the session that can be verified offline.
        """
        if not self.session_key:
            return  # No session established
        
        print("\n" + "=" * 70)
        print("SESSION TEARDOWN (Non-Repudiation)")
        print("=" * 70)
        print("[*] Generating session receipt...")
        
        # Compute transcript hash
        thash = self.transcript.compute_hash()
        
        # Sign hash
        sig = sign.sign(self.priv_key, thash.encode('utf-8'))
        
        # Create receipt
        rcpt = Receipt(
            peer="client",
            first_seq=0,
            last_seq=self.seq_out,
            transcript_sha256=thash,
            sig=b64e(sig)
        )
        
        try:
            # Send receipt to server
            self.send_json(rcpt.model_dump())
            
            # Save transcript
            with open("client_transcript.log", "w") as f:
                f.write(self.transcript.export())
            print("[+] Transcript saved to client_transcript.log")
            
            # Save our receipt
            with open("client_receipt.json", "w") as f:
                json.dump(rcpt.model_dump(), f, indent=2)
            print("[+] Client receipt saved to client_receipt.json")
            
            print()
            print("Evidence Files:")
            print("  - client_transcript.log")
            print("  - client_receipt.json")
            print("  - server_receipt.json")
            print()
            print("Verify with:")
            print("  python verify_receipt.py")
            print("=" * 70)
            
        except OSError as e:
            print(f"[-] Could not send/save receipt: {e}")

    def send_json(self, obj: dict):
        """Sends a JSON message with newline delimiter."""
        raw = json.dumps(obj) + "\n"
        self.sock.sendall(raw.encode('utf-8'))

    def recv_json(self) -> dict:
        """
        Receives a newline-delimited JSON message.
        
        Returns:
            dict: Parsed JSON, or None if connection closed
        """
        if not hasattr(self, 'buffer'):
            self.buffer = b""
        
        while b"\n" not in self.buffer:
            try:
                chunk = self.sock.recv(4096)
                if not chunk:
                    return None
                self.buffer += chunk
            except (OSError, socket.timeout):
                return None
        
        line, self.buffer = self.buffer.split(b"\n", 1)
        return json.loads(line.decode('utf-8'))


def main():
    """
    Main client function.
    
    Orchestrates the complete protocol flow:
    1. Connect and handshake
    2. Authenticate
    3. Chat session
    4. Shutdown and receipts
    """
    client = SecureChatClient()
    
    try:
        # Phase 1: Connect
        client.connect()
        
        # Phase 2: Authenticate
        if not client.authenticate():
            print("[-] Authentication failed")
            return
        
        # Phase 3: Chat
        client.chat_session()
        
    except KeyboardInterrupt:
        print("\n\n[*] Interrupted by user")
    except Exception as e:
        print(f"\n[!] Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # Phase 4: Shutdown
        if client.sock:
            client.perform_shutdown()
            client.sock.close()
        print("\n[+] Client stopped")


if __name__ == "__main__":
    main()

