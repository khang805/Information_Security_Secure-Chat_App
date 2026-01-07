"""Client workflow — plain TCP; no TLS. See assignment spec."""

import os
import json
import socket
import secrets
import hashlib
from pathlib import Path
from dotenv import load_dotenv
from app.common.protocol import (
    Hello, ServerHello, Register, Login, DHClient, DHServer, Msg, Receipt
)
from app.common.utils import now_ms, b64e, b64d, sha256_hex
from app.crypto import pki, aes, sign, dh
from app.storage.transcript import TranscriptLogger, get_cert_fingerprint

load_dotenv()


def load_client_certificates():
    """Load client certificate and key paths."""
    cert_path = Path(os.getenv('CLIENT_CERT_PATH', 'certs/client.crt'))
    key_path = Path(os.getenv('CLIENT_KEY_PATH', 'certs/client.key'))
    ca_cert_path = Path(os.getenv('CA_CERT_PATH', 'certs/ca.crt'))
    
    with open(cert_path, 'r') as f:
        client_cert_pem = f.read()
    
    return client_cert_pem, key_path, ca_cert_path


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


def main():
    """Main client entry point."""
    host = os.getenv('SERVER_HOST', 'localhost')
    port = int(os.getenv('SERVER_PORT', 8888))
    
    # Load client certificates
    client_cert_pem, client_key_path, ca_cert_path = load_client_certificates()
    
    # Connect to server
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((host, port))
        print(f"Connected to server at {host}:{port}")
        
        # Control Plane: Hello exchange
        client_nonce = secrets.token_bytes(16)
        hello = Hello(
            client_cert=client_cert_pem,
            nonce=b64e(client_nonce)
        )
        send_message(sock, hello.model_dump())
        
        # Receive server hello
        server_hello_data = receive_message(sock)
        if 'error' in server_hello_data:
            print(f"Error: {server_hello_data['error']}")
            return
        
        server_hello = ServerHello.model_validate(server_hello_data)
        
        # Validate server certificate
        try:
            pki.validate_certificate(server_hello.server_cert, ca_cert_path, expected_cn="server.local")
            print("Server certificate validated")
        except ValueError as e:
            print(f"Certificate validation failed: {e}")
            return
        
        # Temporary DH exchange for initial encryption
        temp_dh_private = dh.generate_private_key()
        temp_dh_public = dh.compute_public_value(dh.DEFAULT_G, dh.DEFAULT_P, temp_dh_private)
        
        temp_dh_client = DHClient(
            g=dh.DEFAULT_G,
            p=dh.DEFAULT_P,
            A=temp_dh_public
        )
        send_message(sock, temp_dh_client.model_dump())
        
        # Receive server DH response
        temp_dh_server_data = receive_message(sock)
        temp_dh_server = DHServer.model_validate(temp_dh_server_data)
        temp_shared_secret = dh.compute_shared_secret(
            temp_dh_server.B, temp_dh_private, dh.DEFAULT_P
        )
        temp_aes_key = dh.derive_key(temp_shared_secret)
        
        # Handle registration/login
        print("\n1. Register")
        print("2. Login")
        choice = input("Choose (1/2): ").strip()
        
        if choice == '1':
            # Registration
            email = input("Email: ").strip()
            username = input("Username: ").strip()
            password = input("Password: ").strip()
            
            # Generate salt and compute password hash
            salt = secrets.token_bytes(16)
            pwd_hash = hashlib.sha256(salt + password.encode('utf-8')).hexdigest()
            
            # Create register message
            register_data = {
                'type': 'register',
                'email': email,
                'username': username,
                'pwd': pwd_hash,
                'salt': b64e(salt)
            }
            
            # Encrypt registration data
            encrypted_payload = aes.encrypt(
                json.dumps(register_data).encode('utf-8'),
                temp_aes_key
            )
            
            send_message(sock, {'payload': encrypted_payload})
            
            # Receive response
            response = receive_message(sock)
            if 'error' in response:
                print(f"Registration failed: {response['error']}")
                return
            print("Registration successful!")
            
        elif choice == '2':
            # Login
            email = input("Email: ").strip()
            password = input("Password: ").strip()
            
            # Get salt from server (in real implementation, server would provide this)
            # For now, we'll need to request it or use a known approach
            # Actually, the protocol says client sends SHA256(salt||password)
            # But we need the salt first. Let me check the protocol...
            # Actually, looking at the server code, it expects the client to already have the salt
            # This is a design issue. For now, let's assume we can get it from the server
            # or the client stores it locally. For simplicity, let's use a workaround.
            
            # Workaround: Request salt from server first (not in protocol, but needed)
            # Or assume client has salt stored. For demo, let's use a placeholder.
            # Actually, the better approach: client should request salt, or server provides it
            # For now, let's implement a simple version where we assume salt is known
            # In production, this would be handled differently
            
            # For now, let's send a request for salt (not in protocol, but practical)
            # Or we can modify to have server send salt on login request
            # Let me implement a simpler version: client computes hash with a dummy salt first
            # Then server provides actual salt... no, that doesn't work.
            
            # Better: Modify protocol to have server send salt, or client stores it
            # For now, let's implement assuming we can get salt somehow
            # Actually, let me check if there's a way to get salt from email...
            
            # Simplest: Assume client has salt stored locally or request it
            # For demo purposes, let's use a workaround where we send email first
            # and server responds with salt, then we send login
            
            # Actually, re-reading the protocol: Login message has pwd as hex(SHA256(salt||password))
            # So client must know salt. This means either:
            # 1. Client stores salt locally after registration
            # 2. Server provides salt on request
            # 3. Protocol needs modification
            
            # For now, let's implement a version where we request salt:
            send_message(sock, {'type': 'get_salt', 'email': email})
            salt_response = receive_message(sock)
            
            if 'error' in salt_response or 'salt' not in salt_response:
                print("Failed to get salt")
                return
            
            salt = b64d(salt_response['salt'])
            pwd_hash = hashlib.sha256(salt + password.encode('utf-8')).hexdigest()
            
            login_data = {
                'type': 'login',
                'email': email,
                'pwd': pwd_hash,
                'nonce': b64e(secrets.token_bytes(16))
            }
            
            # Encrypt login data
            encrypted_payload = aes.encrypt(
                json.dumps(login_data).encode('utf-8'),
                temp_aes_key
            )
            
            send_message(sock, {'payload': encrypted_payload})
            
            # Receive response
            response = receive_message(sock)
            if 'error' in response:
                print(f"Login failed: {response['error']}")
                return
            print("Login successful!")
        else:
            print("Invalid choice")
            return
        
        # Key Agreement: Session DH exchange
        session_dh_private = dh.generate_private_key()
        session_dh_public = dh.compute_public_value(dh.DEFAULT_G, dh.DEFAULT_P, session_dh_private)
        
        session_dh_client = DHClient(
            g=dh.DEFAULT_G,
            p=dh.DEFAULT_P,
            A=session_dh_public
        )
        send_message(sock, session_dh_client.model_dump())
        
        # Receive server DH response
        session_dh_server_data = receive_message(sock)
        session_dh_server = DHServer.model_validate(session_dh_server_data)
        session_shared_secret = dh.compute_shared_secret(
            session_dh_server.B, session_dh_private, dh.DEFAULT_P
        )
        session_key = dh.derive_key(session_shared_secret)
        
        print("\nSession established! Type messages (or 'quit' to exit):")
        
        # Initialize transcript logger
        transcript_path = Path(f"transcripts/client_{host}_{port}.txt")
        transcript_logger = TranscriptLogger(transcript_path)
        server_cert_fingerprint = get_cert_fingerprint(server_hello.server_cert)
        seqno = 1
        
        # Data Plane: Message exchange loop
        while True:
            message = input("> ").strip()
            if message.lower() == 'quit':
                break
            
            # Encrypt message
            ciphertext = aes.encrypt(message.encode('utf-8'), session_key)
            timestamp = now_ms()
            
            # Compute signature: SHA256(seqno||ts||ct)
            seqno_bytes = seqno.to_bytes(8, byteorder='big')
            ts_bytes = timestamp.to_bytes(8, byteorder='big')
            ct_bytes = ciphertext.encode('utf-8')
            digest_data = seqno_bytes + ts_bytes + ct_bytes
            
            # Sign digest
            signature = sign.sign(digest_data, client_key_path)
            
            # Create message
            msg = Msg(
                seqno=seqno,
                ts=timestamp,
                ct=ciphertext,
                sig=signature
            )
            send_message(sock, msg.model_dump())
            
            # Log to transcript
            transcript_logger.append(
                seqno, timestamp, ciphertext, signature, server_cert_fingerprint
            )
            
            # Receive response
            response = receive_message(sock)
            if 'error' in response:
                print(f"Error: {response['error']}")
                if 'REPLAY' in response['error']:
                    break
            else:
                print(f"Server acknowledged: {response.get('status', 'OK')}")
            
            seqno += 1
        
        # Non-Repudiation: Generate SessionReceipt
        transcript_hash = transcript_logger.compute_hash()
        first_seq = transcript_logger.get_first_seq() or 1
        last_seq = transcript_logger.get_last_seq() or (seqno - 1)
        
        # Sign transcript hash
        receipt_sig = sign.sign(
            transcript_hash.encode('utf-8'),
            client_key_path
        )
        
        receipt = Receipt(
            peer="client",
            first_seq=first_seq,
            last_seq=last_seq,
            transcript_sha256=transcript_hash,
            sig=receipt_sig
        )
        send_message(sock, receipt.model_dump())
        
        # Receive server receipt
        server_receipt_data = receive_message(sock)
        if 'type' in server_receipt_data and server_receipt_data['type'] == 'receipt':
            server_receipt = Receipt.model_validate(server_receipt_data)
            print(f"\nServer receipt received:")
            print(f"  First seq: {server_receipt.first_seq}")
            print(f"  Last seq: {server_receipt.last_seq}")
            print(f"  Transcript hash: {server_receipt.transcript_sha256}")
            
            # Save server receipt to file
            server_receipt_path = Path(f"transcripts/server_receipt_{host}_{port}.json")
            server_receipt_path.parent.mkdir(parents=True, exist_ok=True)
            with open(server_receipt_path, 'w') as f:
                json.dump(server_receipt_data, f, indent=2)
            print(f"  Server receipt saved to: {server_receipt_path}")
        
        # Save client receipt to file
        client_receipt_path = Path(f"transcripts/client_receipt_{host}_{port}.json")
        client_receipt_path.parent.mkdir(parents=True, exist_ok=True)
        with open(client_receipt_path, 'w') as f:
            json.dump(receipt.model_dump(), f, indent=2)
        print(f"\nClient receipt saved to: {client_receipt_path}")
        
        # Export transcript
        transcript_export_path = transcript_logger.export()
        print(f"Transcript exported to: {transcript_export_path}")
        print(f"\nSession completed. All files saved in transcripts/ directory.")
        
    except Exception as e:
        print(f"Error: {e}")
    finally:
        sock.close()


if __name__ == "__main__":
    main()
