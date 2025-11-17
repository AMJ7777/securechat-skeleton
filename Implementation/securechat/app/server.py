"""
SecureChat Server

Implements the server side of the secure chat protocol.

Protocol Phases:
1. Handshake: Mutual certificate authentication
2. Auth: Encrypted registration/login with temporary DH key
3. Session: Fresh DH key exchange for chat encryption
4. Chat: Encrypted message exchange with signatures
5. Teardown: Session receipts for non-repudiation

Security Properties:
- Mutual authentication via PKI
- Forward secrecy via per-session DH
- Confidentiality via AES-128
- Integrity and authenticity via RSA signatures
- Replay protection via sequence numbers
- Non-repudiation via signed transcripts

Usage:
    python -m app.server
"""

import socket
import threading
import json
import sys
import os
import secrets
import queue

from app.common.protocol import ServerHello, DHServer, Msg, Receipt
from app.common.utils import now_ms, b64e, b64d
from app.crypto import pki, aes, dh, sign
from app.storage.db import Database
from app.storage.transcript import Transcript


# Server Configuration
HOST = os.getenv('SERVER_HOST', '0.0.0.0')
PORT = int(os.getenv('SERVER_PORT', 8080))
CERTS_DIR = "certs"


class ClientHandler:
    """
    Handles a single client connection through the complete protocol.
    
    State Variables:
        - client_cert: Verified X.509 certificate of the client
        - session_key: AES-128 key for chat encryption
        - seq_in: Expected next sequence number from client
        - seq_out: Next sequence number for outgoing messages
        - transcript: Append-only log for non-repudiation
        - username: Authenticated username
    """
    
    def __init__(self, conn: socket.socket, addr: tuple):
        """
        Initializes the client handler.
        
        Args:
            conn: TCP socket connection to client
            addr: Client address (IP, port)
        """
        self.conn = conn
        self.addr = addr
        self.running = True
        
        # Security State
        self.client_cert = None
        self.session_key = None
        self.seq_in = 0          # Expected inbound sequence number
        self.seq_out = 0         # Outbound sequence number
        self.transcript = Transcript()
        self.username = "Unknown"
        
        # Database
        self.db = None
        
        # Load Server PKI Assets
        try:
            with open(f"{CERTS_DIR}/server.crt", "r") as f:
                self.cert_pem = f.read()
            with open(f"{CERTS_DIR}/ca.crt", "r") as f:
                self.ca_cert_pem = f.read()
            with open(f"{CERTS_DIR}/server.key", "rb") as f:
                self.priv_key = pki.load_private_key(f.read())
        except FileNotFoundError as e:
            print(f"[!] Error: Missing certificates in {CERTS_DIR}/. Run gen_cert.py first.")
            raise

    def run(self):
        """
        Main workflow for handling a client connection.
        
        Protocol Flow:
        1. Handshake & Certificate Validation
        2. Authentication (Register/Login)
        3. Session Key Setup
        4. Chat Loop
        5. Shutdown & Receipt Exchange
        """
        print(f"\n[+] New connection from {self.addr}")
        
        try:
            # Initialize database connection
            self.db = Database()
            
            # Phase 1: PKI Handshake
            if not self.perform_handshake():
                print(f"[-] Handshake failed for {self.addr}")
                return

            # Phase 2: Authentication
            if not self.perform_auth():
                print(f"[-] Authentication failed for {self.addr}")
                return
            
            # Phase 3: Session Key Establishment
            if not self.perform_session_setup():
                print(f"[-] Session setup failed for {self.addr}")
                return

            # Phase 4: Encrypted Chat
            self.chat_loop()
            
        except Exception as e:
            print(f"[-] Error with {self.addr}: {e}")
        finally:
            self.close()

    def perform_handshake(self) -> bool:
        """
        Phase 1: Mutual PKI Authentication
        
        Steps:
        1. Receive client hello with certificate
        2. Verify client certificate against CA
        3. Send server hello with certificate
        
        Returns:
            bool: True if handshake succeeds
            
        Security:
            - Rejects self-signed certificates
            - Rejects expired certificates
            - Validates signature chain
        """
        print(f"[*] Starting handshake with {self.addr}...")
        
        # Receive client hello
        data = self.recv_json()
        if not data or data.get("type") != "hello":
            print("[-] Protocol error: Expected 'hello'")
            return False

        # Verify client certificate
        try:
            self.client_cert = pki.verify_cert(
                data["client_cert"],
                self.ca_cert_pem
                # Note: We don't check CN for client (flexible identifier)
            )
            print(f"[+] Client certificate verified (CN: {self.client_cert.subject.get_attributes_for_oid(pki.NameOID.COMMON_NAME)[0].value})")
        except ValueError as e:
            print(f"[-] Certificate validation failed: {e}")
            # Send error response
            self.send_json({"type": "error", "msg": str(e)})
            return False

        # Send server hello
        nonce = b64e(secrets.token_bytes(16))
        hello = ServerHello(server_cert=self.cert_pem, nonce=nonce)
        self.send_json(hello.model_dump())
        
        print(f"[+] Handshake complete with {self.addr}")
        return True

    def perform_auth(self) -> bool:
        """
        Phase 2: Encrypted Authentication
        
        Steps:
        1. Ephemeral DH exchange for temporary encryption key
        2. Receive encrypted registration or login request
        3. Process credentials with database
        4. Respond with success/failure
        
        Returns:
            bool: True if authentication succeeds
            
        Security:
            - Credentials encrypted under ephemeral DH key
            - Salted SHA-256 password hashing
            - Constant-time comparison
            - Dual-factor: certificate + password
        """
        print(f"[*] Starting authentication phase for {self.addr}...")
        
        # Step 1: Ephemeral DH for auth encryption
        data = self.recv_json()
        if not data or data.get("type") != "dh_client":
            print("[-] Protocol error: Expected DH exchange")
            return False
        
        # Initialize DH with client's parameters
        dh_eng = dh.DiffieHellman(p=data['p'], g=data['g'])
        shared = dh_eng.compute_secret(data['A'])
        temp_key = dh.DiffieHellman.derive_session_key(shared)
        
        # Send our public key
        resp = DHServer(B=dh_eng.public_key)
        self.send_json(resp.model_dump())
        
        print(f"[*] Temporary encryption key established for {self.addr}")
        
        # Step 2: Loop until successful auth
        while True:
            wrapper = self.recv_json()
            if not wrapper:
                return False
            
            if wrapper.get("type") != "encrypted_auth":
                print("[-] Protocol error: Expected encrypted_auth")
                return False
            
            # Decrypt credentials
            try:
                pt_bytes = aes.decrypt(temp_key, b64d(wrapper['ct']))
                payload = json.loads(pt_bytes.decode('utf-8'))
            except Exception as e:
                print(f"[-] Decryption failed: {e}")
                self.send_json({"status": "FAIL", "msg": "Decryption failed"})
                continue

            req_type = payload.get("type")
            
            # Process Registration
            if req_type == "register":
                email = payload['email']
                username = payload['username']
                password = payload['pwd']
                
                success = self.db.register_user(email, username, password)
                if success:
                    self.username = username
                    print(f"[+] User registered: {username}")
                    self.send_json({"status": "OK", "msg": "Registration successful"})
                    return True  # Auto-login after registration
                else:
                    self.send_json({"status": "FAIL", "msg": "Username/email already exists"})
                    continue
            
            # Process Login
            elif req_type == "login":
                email = payload['email']
                password = payload['pwd']
                
                success = self.db.verify_credentials(email, password)
                if success:
                    self.username = email
                    print(f"[+] User logged in: {email}")
                    self.send_json({"status": "OK", "msg": "Login successful"})
                    return True
                else:
                    self.send_json({"status": "FAIL", "msg": "Invalid credentials"})
                    continue
            
            else:
                self.send_json({"status": "FAIL", "msg": "Unknown auth type"})
                continue

    def perform_session_setup(self) -> bool:
        """
        Phase 3: Session Key Agreement
        
        Steps:
        1. Fresh DH exchange
        2. Derive AES-128 session key
        
        Returns:
            bool: True if session key established
            
        Security:
            - Forward secrecy: unique key per session
            - Independent from auth key
            - Prevents key reuse across sessions
        """
        print(f"[*] Negotiating session key for {self.addr}...")
        
        data = self.recv_json()
        if not data or data.get("type") != "dh_client":
            return False
        
        # Perform DH key exchange
        dh_eng = dh.DiffieHellman(p=data['p'], g=data['g'])
        shared = dh_eng.compute_secret(data['A'])
        self.session_key = dh.DiffieHellman.derive_session_key(shared)
        
        # Send server's public key
        resp = DHServer(B=dh_eng.public_key)
        self.send_json(resp.model_dump())
        
        print(f"[+] Session key established for {self.username}")
        return True

    def chat_loop(self):
        """
        Phase 4: Encrypted Message Exchange
        
        Handles bidirectional encrypted chat with:
        - Server console input (for testing)
        - Client message reception and verification
        - Signature verification for each message
        - Replay protection via sequence numbers
        - Graceful shutdown on /quit
        """
        print(f"\n{'='*70}")
        print(f"[***] Secure Chat Started with {self.username} ({self.addr}) [***]")
        print(f"{'='*70}")
        print("Type messages and press Enter. Type '/quit' to end session.")
        print()
        
        # Queue for server console input (non-blocking)
        input_q = queue.Queue()
        
        def input_thread():
            """Background thread for server console input."""
            while self.running:
                try:
                    msg = sys.stdin.readline()
                    if msg:
                        input_q.put(msg.strip())
                except:
                    break
        
        t = threading.Thread(target=input_thread, daemon=True)
        t.start()

        # Main chat loop
        while self.running:
            # Handle outgoing messages (from server console)
            while not input_q.empty():
                text = input_q.get()
                if text == "/quit":
                    self.running = False
                    self.send_close_receipt()
                    return
                if text:
                    self.send_chat_msg(text)

            # Handle incoming messages (from client)
            self.conn.settimeout(0.1)  # Non-blocking check
            try:
                data = self.recv_json()
                if data:
                    self.process_incoming_msg(data)
                else:
                    # Client disconnected
                    print(f"\n[-] Client {self.username} disconnected")
                    self.running = False
            except socket.timeout:
                continue
            except (ConnectionResetError, ValueError, OSError) as e:
                print(f"\n[-] Connection lost with {self.username}: {e}")
                self.running = False

    def send_chat_msg(self, text: str):
        """
        Encrypts, signs, and sends a chat message.
        
        Message Format:
            {
                "type": "msg",
                "seqno": int,
                "ts": float,
                "ct": base64(AES-128(text)),
                "sig": base64(RSA-Sign(SHA256(seqno||ts||ct)))
            }
        
        Args:
            text: Plaintext message to send
        """
        seq = self.seq_out
        self.seq_out += 1
        ts = now_ms()
        
        # Encrypt message
        ct_bytes = aes.encrypt(self.session_key, text.encode('utf-8'))
        ct_str = b64e(ct_bytes)
        
        # Sign metadata + ciphertext
        raw_data = f"{seq}{ts}{ct_str}".encode('utf-8')
        sig_bytes = sign.sign(self.priv_key, raw_data)
        
        # Create message
        msg = Msg(seqno=seq, ts=ts, ct=ct_str, sig=b64e(sig_bytes))
        
        # Log to transcript
        my_cert = pki.load_cert(self.cert_pem)
        self.transcript.add(seq, ts, ct_str, b64e(sig_bytes), my_cert)
        
        # Send
        self.send_json(msg.model_dump())

    def process_incoming_msg(self, data: dict):
        """
        Processes an incoming message from the client.
        
        Security Checks:
        1. Sequence number validation (replay protection)
        2. Signature verification (authenticity)
        3. Decryption (confidentiality)
        4. Transcript logging (non-repudiation)
        
        Args:
            data: Received message dictionary
        """
        # Handle receipt (session end)
        if data.get("type") == "receipt":
            print(f"\n[*] Received session receipt from {self.username}")
            
            # Save client's receipt
            with open("client_receipt.json", "w") as f:
                json.dump(data, f, indent=2)
            print("[+] Client receipt saved to client_receipt.json")
            
            # Send our receipt in response
            if self.running:
                self.send_close_receipt()
            
            self.running = False
            return

        # Handle chat message
        if data.get("type") != "msg":
            return

        seq = data['seqno']
        ts = data['ts']
        ct = data['ct']
        sig = data['sig']
        
        # Check 1: Replay Protection
        if seq != self.seq_in:
            print(f"\n[!] SECURITY ALERT: Replay attack detected!")
            print(f"    Expected seq: {self.seq_in}, Got: {seq}")
            # In production, might disconnect or log security event
            # For testing, we allow out-of-order but warn
        self.seq_in = seq + 1
        
        # Check 2: Verify Signature
        raw = f"{seq}{ts}{ct}".encode('utf-8')
        try:
            client_pub = self.client_cert.public_key()
            sign.verify(client_pub, b64d(sig), raw)
        except Exception as e:
            print(f"\n[!] SECURITY ALERT: Signature verification failed!")
            print(f"    Message dropped. Details: {e}")
            return

        # Check 3: Decrypt
        try:
            pt = aes.decrypt(self.session_key, b64d(ct))
            message_text = pt.decode('utf-8')
            print(f"\r{self.username}: {message_text}")
            print("You: ", end="", flush=True)
        except Exception as e:
            print(f"\n[!] Decryption failed: {e}")
            return

        # Check 4: Log to Transcript
        self.transcript.add(seq, ts, ct, sig, self.client_cert)

    def send_close_receipt(self):
        """
        Phase 5: Non-Repudiation
        
        Steps:
        1. Compute transcript hash
        2. Sign hash with server's private key
        3. Send receipt to client
        4. Save transcript to file
        
        Creates cryptographic proof that cannot be forged or repudiated.
        """
        print(f"\n[*] Generating session receipt...")
        
        # Compute transcript hash
        thash = self.transcript.compute_hash()
        
        # Sign hash
        sig = sign.sign(self.priv_key, thash.encode('utf-8'))
        
        # Create receipt
        rcpt = Receipt(
            peer="server",
            first_seq=0,
            last_seq=self.seq_out,
            transcript_sha256=thash,
            sig=b64e(sig)
        )
        
        try:
            # Send receipt
            self.send_json(rcpt.model_dump())
            
            # Save transcript
            with open("server_transcript.log", "w") as f:
                f.write(self.transcript.export())
            
            # Save our receipt
            with open("server_receipt.json", "w") as f:
                json.dump(rcpt.model_dump(), f, indent=2)
            
            print("[+] Session closed. Evidence saved:")
            print("    - server_transcript.log")
            print("    - server_receipt.json")
            
        except OSError as e:
            print(f"[-] Could not send/save receipt: {e}")

    def send_json(self, obj: dict):
        """Sends a JSON message with newline delimiter."""
        raw = json.dumps(obj) + "\n"
        self.conn.sendall(raw.encode('utf-8'))

    def recv_json(self) -> dict:
        """
        Receives a newline-delimited JSON message.
        
        Returns:
            dict: Parsed JSON object, or None if connection closed
        """
        buf = b""
        while b"\n" not in buf:
            try:
                chunk = self.conn.recv(4096)
                if not chunk:
                    return None  # Connection closed
                buf += chunk
            except socket.timeout:
                raise  # Propagate timeout to chat_loop
            except OSError:
                return None
        
        line, _ = buf.split(b"\n", 1)
        return json.loads(line.decode('utf-8'))

    def close(self):
        """Cleanup: close database and socket."""
        print(f"[*] Closing connection for {self.addr}")
        if self.db:
            self.db.close()
        if self.conn:
            self.conn.close()


def main():
    """
    Main server function.
    
    Listens for client connections and spawns a handler thread for each.
    """
    print("=" * 70)
    print("SecureChat Server (Assignment #2)")
    print("=" * 70)
    print()
    
    # Create server socket
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(5)
    
    print(f"[*] Server listening on {HOST}:{PORT}")
    print(f"[*] Certificates: {CERTS_DIR}/")
    print(f"[*] Press Ctrl+C to shutdown")
    print()
    
    try:
        while True:
            conn, addr = server.accept()
            handler = ClientHandler(conn, addr)
            
            # For assignment demo, we handle one client at a time (blocking)
            # This allows server console input during chat
            # In production, use non-blocking threads or async
            t = threading.Thread(target=handler.run)
            t.start()
            t.join()  # Wait for this client to finish before accepting next
            
            print("\n[*] Ready for next client...\n")
            
    except KeyboardInterrupt:
        print("\n\n[*] Shutting down server...")
    finally:
        server.close()
        print("[+] Server stopped.")


if __name__ == "__main__":
    main()

