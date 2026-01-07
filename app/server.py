"""Server workflow — plain TCP; no TLS. See assignment spec."""

import os
import json
import socket
import secrets
from pathlib import Path
from dotenv import load_dotenv
from app.common.protocol import (
    Hello, ServerHello, Register, Login, DHClient, DHServer, Msg, Receipt
)
from app.common.utils import now_ms, b64e, b64d, sha256_hex
from app.crypto import pki, aes, sign, dh
from app.storage import db
from app.storage.transcript import TranscriptLogger, get_cert_fingerprint

load_dotenv()


def load_server_certificates():
    """Load server certificate and key paths."""
    cert_path = Path(os.getenv('SERVER_CERT_PATH', 'certs/server.crt'))
    key_path = Path(os.getenv('SERVER_KEY_PATH', 'certs/server.key'))
    ca_cert_path = Path(os.getenv('CA_CERT_PATH', 'certs/ca.crt'))
    
    with open(cert_path, 'r') as f:
        server_cert_pem = f.read()
    
    return server_cert_pem, key_path, ca_cert_path


def send_message(sock: socket.socket, message: dict):
    """Send JSON message over socket."""
    data = json.dumps(message).encode('utf-8')
    sock.sendall(data + b'\n')


def receive_message(sock: socket.socket) -> dict:
    """Receive JSON message from socket."""
    buffer = b''
    while b'\n' not in buffer:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("Connection closed")
        buffer += chunk
    line = buffer.split(b'\n', 1)[0]
    return json.loads(line.decode('utf-8'))


def handle_client(sock: socket.socket, addr):
    """Handle complete client session."""
    print(f"Client connected from {addr}")
    session_key = None
    last_seqno = 0
    client_cert_pem = None
    
    try:
        # Load server certificates
        server_cert_pem, server_key_path, ca_cert_path = load_server_certificates()
        
        # Control Plane: Hello exchange
        hello_data = receive_message(sock)
        hello = Hello.model_validate(hello_data)
        client_cert_pem = hello.client_cert
        
        # Validate client certificate
        try:
            pki.validate_certificate(client_cert_pem, ca_cert_path)
        except ValueError as e:
            send_message(sock, {"error": str(e)})
            return
        
        # Send server hello
        server_nonce = secrets.token_bytes(16)
        server_hello = ServerHello(
            server_cert=server_cert_pem,
            nonce=b64e(server_nonce)
        )
        send_message(sock, server_hello.model_dump())
        
        # Temporary DH exchange for initial encryption
        temp_dh_private = dh.generate_private_key()
        temp_dh_public = dh.compute_public_value(dh.DEFAULT_G, dh.DEFAULT_P, temp_dh_private)
        
        # Receive client DH params for temp key
        temp_dh_data = receive_message(sock)
        temp_dh_client = DHClient.model_validate(temp_dh_data)
        temp_shared_secret = dh.compute_shared_secret(
            temp_dh_client.A, temp_dh_private, temp_dh_client.p
        )
        temp_aes_key = dh.derive_key(temp_shared_secret)
        
        # Send server DH response
        temp_dh_server = DHServer(B=temp_dh_public)
        send_message(sock, temp_dh_server.model_dump())
        
        # Handle register/login (encrypted under temp AES key)
        # First, check if client is requesting salt for login
        auth_request = receive_message(sock)
        
        # Handle salt request for login
        if auth_request.get('type') == 'get_salt':
            email = auth_request.get('email')
            if not email:
                send_message(sock, {"error": "Missing email"})
                return
            salt = db.get_user_salt(email)
            if salt:
                send_message(sock, {"salt": b64e(salt)})
            else:
                send_message(sock, {"error": "User not found"})
                return
            # Receive encrypted login after salt request
            encrypted_auth_data = receive_message(sock)
        else:
            encrypted_auth_data = auth_request
        
        encrypted_payload = encrypted_auth_data.get('payload', '')
        if not encrypted_payload:
            send_message(sock, {"error": "Missing encrypted payload"})
            return
        
        # Decrypt authentication data
        try:
            decrypted_bytes = aes.decrypt(encrypted_payload, temp_aes_key)
            auth_data = json.loads(decrypted_bytes.decode('utf-8'))
        except Exception as e:
            send_message(sock, {"error": f"Decryption failed: {e}"})
            return
        
        if auth_data.get('type') == 'register':
            try:
                # Register message: pwd is hex(SHA256(salt||password))
                # We need to store this directly in the database
                # But db.register_user expects plaintext password
                # Workaround: Store the hash as-is (modify db layer would be better)
                # For now, we'll need to handle this differently
                email = auth_data['email']
                username = auth_data['username']
                pwd_hash_hex = auth_data['pwd']  # Already hashed
                salt_bytes = b64d(auth_data['salt'])
                
                # Store directly - we'll need a modified register function
                # For now, use a workaround by storing hash directly
                import pymysql
                conn = db.get_db_connection()
                try:
                    with conn.cursor() as cursor:
                        cursor.execute("SELECT username FROM users WHERE username = %s", (username,))
                        if cursor.fetchone():
                            raise ValueError(f"Username '{username}' already exists")
                        cursor.execute("SELECT email FROM users WHERE email = %s", (email,))
                        if cursor.fetchone():
                            raise ValueError(f"Email '{email}' already registered")
                        cursor.execute(
                            "INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s, %s, %s, %s)",
                            (email, username, salt_bytes, pwd_hash_hex)
                        )
                    conn.commit()
                    send_message(sock, {"status": "registered"})
                except Exception as e:
                    conn.rollback()
                    send_message(sock, {"error": str(e)})
                    return
                finally:
                    conn.close()
            except ValueError as e:
                send_message(sock, {"error": str(e)})
                return
        elif auth_data.get('type') == 'login':
            login_email = auth_data['email']
            login_pwd_hash = auth_data['pwd']  # hex(SHA256(salt||password))
            salt = db.get_user_salt(login_email)
            if not salt:
                send_message(sock, {"error": "Invalid credentials"})
                return
            # Verify login
            if db.verify_login(login_email, login_pwd_hash, salt):
                send_message(sock, {"status": "logged_in"})
            else:
                send_message(sock, {"error": "Invalid credentials"})
                return
        else:
            send_message(sock, {"error": "Invalid message type"})
            return
        
        # Key Agreement: Session DH exchange
        dh_data = receive_message(sock)
        dh_client = DHClient.model_validate(dh_data)
        
        # Generate server DH private key
        server_dh_private = dh.generate_private_key()
        server_dh_public = dh.compute_public_value(
            dh_client.g, dh_client.p, server_dh_private
        )
        
        # Compute shared secret and derive session key
        shared_secret = dh.compute_shared_secret(
            dh_client.A, server_dh_private, dh_client.p
        )
        session_key = dh.derive_key(shared_secret)
        
        # Send server DH response
        dh_server = DHServer(B=server_dh_public)
        send_message(sock, dh_server.model_dump())
        
        # Initialize transcript logger
        transcript_path = Path(f"transcripts/server_{addr[0]}_{addr[1]}.txt")
        transcript_logger = TranscriptLogger(transcript_path)
        client_cert_fingerprint = get_cert_fingerprint(client_cert_pem)
        
        # Data Plane: Message exchange loop
        print("Session established. Waiting for messages...")
        while True:
            msg_data = receive_message(sock)
            
            if msg_data.get('type') == 'receipt':
                # Client sent receipt, session ending
                break
            
            msg = Msg.model_validate(msg_data)
            
            # Replay protection
            if msg.seqno <= last_seqno:
                send_message(sock, {"error": "REPLAY: Sequence number must be strictly increasing"})
                continue
            last_seqno = msg.seqno
            
            # Verify signature using client certificate from hello
            # Signature is over SHA256(seqno||ts||ct) - concatenate as bytes
            seqno_bytes = msg.seqno.to_bytes(8, byteorder='big')
            ts_bytes = msg.ts.to_bytes(8, byteorder='big')
            ct_bytes = msg.ct.encode('utf-8')
            digest_data = seqno_bytes + ts_bytes + ct_bytes
            
            try:
                # Save client cert temporarily for verification
                import tempfile
                with tempfile.NamedTemporaryFile(mode='w', suffix='.crt', delete=False) as f:
                    f.write(client_cert_pem)
                    temp_cert_path = Path(f.name)
                try:
                    sign.verify(digest_data, msg.sig, temp_cert_path)
                finally:
                    temp_cert_path.unlink()
            except ValueError as e:
                send_message(sock, {"error": str(e)})
                continue
            
            # Decrypt message
            try:
                plaintext = aes.decrypt(msg.ct, session_key)
                print(f"Received: {plaintext.decode('utf-8', errors='ignore')}")
            except Exception as e:
                send_message(sock, {"error": f"Decryption failed: {e}"})
                continue
            
            # Log to transcript
            transcript_logger.append(
                msg.seqno, msg.ts, msg.ct, msg.sig, client_cert_fingerprint
            )
            
            # Echo response (optional)
            send_message(sock, {"status": "received", "seqno": msg.seqno})
        
        # Non-Repudiation: Generate SessionReceipt
        transcript_hash = transcript_logger.compute_hash()
        first_seq = transcript_logger.get_first_seq() or 0
        last_seq = transcript_logger.get_last_seq() or 0
        
        # Sign transcript hash
        receipt_sig = sign.sign(
            transcript_hash.encode('utf-8'),
            server_key_path
        )
        
        receipt = Receipt(
            peer="server",
            first_seq=first_seq,
            last_seq=last_seq,
            transcript_sha256=transcript_hash,
            sig=receipt_sig
        )
        send_message(sock, receipt.model_dump())
        
        # Save server receipt to file
        receipt_path = Path(f"transcripts/server_receipt_{addr[0]}_{addr[1]}.json")
        receipt_path.parent.mkdir(parents=True, exist_ok=True)
        with open(receipt_path, 'w') as f:
            json.dump(receipt.model_dump(), f, indent=2)
        print(f"Server receipt saved to: {receipt_path}")
        
        # Export transcript
        transcript_export_path = transcript_logger.export()
        print(f"Transcript exported to: {transcript_export_path}")
        print(f"Session completed. All files saved in transcripts/ directory.")
        
    except Exception as e:
        print(f"Error handling client: {e}")
        try:
            send_message(sock, {"error": str(e)})
        except:
            pass
    finally:
        sock.close()
        print(f"Client {addr} disconnected")


def main():
    """Main server entry point."""
    host = os.getenv('SERVER_HOST', 'localhost')
    port = int(os.getenv('SERVER_PORT', 8888))
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(5)
    
    print(f"Server listening on {host}:{port}")
    
    try:
        while True:
            client_sock, addr = server_socket.accept()
            handle_client(client_sock, addr)
    except KeyboardInterrupt:
        print("\nServer shutting down...")
    finally:
        server_socket.close()


if __name__ == "__main__":
    main()
