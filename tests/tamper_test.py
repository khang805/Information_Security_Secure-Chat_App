"""Tamper test: Modify ciphertext to demonstrate SIG_FAIL error."""

import os
import sys
import json
import socket
import secrets
import hashlib
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from dotenv import load_dotenv
from app.common.protocol import Hello, ServerHello, DHClient, DHServer, Msg
from app.common.utils import now_ms, b64e, b64d
from app.crypto import pki, aes, sign, dh

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


def tamper_ciphertext(ciphertext_b64: str) -> str:
    """Tamper with ciphertext by flipping a bit."""
    ciphertext_bytes = b64d(ciphertext_b64)
    # Flip last bit of first byte
    tampered_bytes = bytearray(ciphertext_bytes)
    tampered_bytes[0] ^= 1  # Flip least significant bit
    return b64e(bytes(tampered_bytes))


def main():
    """Test tampering detection."""
    host = os.getenv('SERVER_HOST', 'localhost')
    port = int(os.getenv('SERVER_PORT', 8888))
    
    client_cert_pem, client_key_path, ca_cert_path = load_client_certificates()
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((host, port))
        print(f"Connected to server at {host}:{port}")
        
        # Control Plane: Hello exchange
        client_nonce = secrets.token_bytes(16)
        hello = Hello(client_cert=client_cert_pem, nonce=b64e(client_nonce))
        send_message(sock, hello.model_dump())
        
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
        
        # Temporary DH exchange
        temp_dh_private = dh.generate_private_key()
        temp_dh_public = dh.compute_public_value(dh.DEFAULT_G, dh.DEFAULT_P, temp_dh_private)
        temp_dh_client = DHClient(g=dh.DEFAULT_G, p=dh.DEFAULT_P, A=temp_dh_public)
        send_message(sock, temp_dh_client.model_dump())
        
        temp_dh_server_data = receive_message(sock)
        temp_dh_server = DHServer.model_validate(temp_dh_server_data)
        temp_shared_secret = dh.compute_shared_secret(temp_dh_server.B, temp_dh_private, dh.DEFAULT_P)
        temp_aes_key = dh.derive_key(temp_shared_secret)
        
        # Login (required by server)
        print("\n=== TAMPER TEST ===")
        print("Performing login...")
        
        # Request salt for login
        email = input("Enter email for login: ").strip()
        password = input("Enter password: ").strip()
        
        send_message(sock, {'type': 'get_salt', 'email': email})
        salt_response = receive_message(sock)
        
        if 'error' in salt_response or 'salt' not in salt_response:
            print(f"Failed to get salt: {salt_response}")
            return
        
        salt = b64d(salt_response['salt'])
        pwd_hash = hashlib.sha256(salt + password.encode('utf-8')).hexdigest()
        
        login_data = {
            'type': 'login',
            'email': email,
            'pwd': pwd_hash,
            'nonce': b64e(secrets.token_bytes(16))
        }
        
        encrypted_payload = aes.encrypt(
            json.dumps(login_data).encode('utf-8'),
            temp_aes_key
        )
        
        send_message(sock, {'payload': encrypted_payload})
        
        login_response = receive_message(sock)
        if 'error' in login_response:
            print(f"Login failed: {login_response['error']}")
            return
        print("Login successful!")
        
        # Session DH exchange
        session_dh_private = dh.generate_private_key()
        session_dh_public = dh.compute_public_value(dh.DEFAULT_G, dh.DEFAULT_P, session_dh_private)
        session_dh_client = DHClient(g=dh.DEFAULT_G, p=dh.DEFAULT_P, A=session_dh_public)
        send_message(sock, session_dh_client.model_dump())
        
        session_dh_server_data = receive_message(sock)
        session_dh_server = DHServer.model_validate(session_dh_server_data)
        session_shared_secret = dh.compute_shared_secret(session_dh_server.B, session_dh_private, dh.DEFAULT_P)
        session_key = dh.derive_key(session_shared_secret)
        
        print("Session key established")
        
        # Send normal message first
        print("\n1. Sending normal (valid) message...")
        message = "Hello, this is a test message"
        ciphertext = aes.encrypt(message.encode('utf-8'), session_key)
        timestamp = now_ms()
        seqno = 1
        
        seqno_bytes = seqno.to_bytes(8, byteorder='big')
        ts_bytes = timestamp.to_bytes(8, byteorder='big')
        ct_bytes = ciphertext.encode('utf-8')
        digest_data = seqno_bytes + ts_bytes + ct_bytes
        signature = sign.sign(digest_data, client_key_path)
        
        msg = Msg(seqno=seqno, ts=timestamp, ct=ciphertext, sig=signature)
        send_message(sock, msg.model_dump())
        
        response = receive_message(sock)
        if 'error' in response:
            print(f"   Error: {response['error']}")
        else:
            print(f"   Success: {response.get('status', 'OK')}")
        
        # Now send tampered message
        print("\n2. Sending TAMPERED message (flipped bit in ciphertext)...")
        message2 = "This message will be tampered"
        ciphertext2 = aes.encrypt(message2.encode('utf-8'), session_key)
        timestamp2 = now_ms()
        seqno2 = 2
        
        # Create signature over ORIGINAL ciphertext
        seqno_bytes2 = seqno2.to_bytes(8, byteorder='big')
        ts_bytes2 = timestamp2.to_bytes(8, byteorder='big')
        ct_bytes2_original = ciphertext2.encode('utf-8')
        digest_data2 = seqno_bytes2 + ts_bytes2 + ct_bytes2_original
        signature2 = sign.sign(digest_data2, client_key_path)  # Sign original
        
        # NOW tamper the ciphertext AFTER signing
        tampered_ciphertext = tamper_ciphertext(ciphertext2)  # Tamper AFTER signature created
        
        # Send tampered ciphertext with ORIGINAL signature
        # Server will compute hash over tampered ciphertext, but signature is over original
        # This will cause signature verification to fail
        tampered_msg = Msg(seqno=seqno2, ts=timestamp2, ct=tampered_ciphertext, sig=signature2)
        send_message(sock, tampered_msg.model_dump())
        
        response2 = receive_message(sock)
        if 'error' in response2:
            error_msg = response2['error']
            if 'SIG_FAIL' in error_msg:
                print(f"   ✓ TAMPER DETECTED: {error_msg}")
                print("   ✓ Signature verification failed as expected!")
            else:
                print(f"   Error: {error_msg}")
        else:
            print(f"   Unexpected success: {response2}")
        
        print("\n=== TEST COMPLETE ===")
        print("Evidence: SIG_FAIL error demonstrates tamper detection")
        
    except Exception as e:
        print(f"Error: {e}")
    finally:
        sock.close()


if __name__ == "__main__":
    main()

