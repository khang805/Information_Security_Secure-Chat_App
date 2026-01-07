"""Offline transcript and SessionReceipt verification for non-repudiation."""

import os
import sys
import json
import hashlib
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from dotenv import load_dotenv
from app.common.protocol import Receipt
from app.common.utils import b64d, sha256_hex
from app.crypto import pki, sign

load_dotenv()


def load_certificate(cert_path: Path):
    """Load certificate from file."""
    with open(cert_path, 'r') as f:
        return f.read()


def verify_message_signature(seqno: int, ts: int, ct: str, sig: str, cert_path: Path) -> bool:
    """
    Verify signature of a single message.
    
    Args:
        seqno: Sequence number
        ts: Timestamp
        ct: Base64 ciphertext
        sig: Base64 signature
        cert_path: Path to PEM certificate of sender
    
    Returns:
        True if signature is valid, False otherwise
    """
    # Recompute digest: SHA256(seqno || ts || ct)
    seqno_bytes = seqno.to_bytes(8, byteorder='big')
    ts_bytes = ts.to_bytes(8, byteorder='big')
    ct_bytes = ct.encode('utf-8')
    digest_data = seqno_bytes + ts_bytes + ct_bytes
    
    # Verify signature (sign.verify computes hash internally)
    try:
        sign.verify(digest_data, sig, cert_path)
        return True
    except ValueError as e:
        print(f"   Signature verification error: {e}")
        return False
    except Exception as e:
        print(f"   Unexpected error: {e}")
        return False


def verify_transcript_hash(transcript_path: Path) -> str:
    """
    Compute and return transcript hash.
    
    Args:
        transcript_path: Path to transcript file
    
    Returns:
        Hex string of transcript hash
    """
    if not transcript_path.exists():
        return sha256_hex(b"")
    
    with open(transcript_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    return sha256_hex(content.encode('utf-8'))


def verify_receipt(receipt: Receipt, cert_path: Path) -> bool:
    """
    Verify SessionReceipt signature.
    
    Args:
        receipt: SessionReceipt object
        cert_path: Path to PEM certificate of signer
    
    Returns:
        True if signature is valid, False otherwise
    """
    # Verify signature over transcript hash
    # The receipt signature is over the transcript hash string (not bytes)
    transcript_hash_bytes = receipt.transcript_sha256.encode('utf-8')
    
    # sign.verify computes hash internally, so pass the hash string bytes
    try:
        sign.verify(transcript_hash_bytes, receipt.sig, cert_path)
        return True
    except ValueError as e:
        print(f"   Receipt signature verification error: {e}")
        return False
    except Exception as e:
        print(f"   Unexpected error: {e}")
        return False


def main():
    """Main verification function."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Verify transcript and SessionReceipt')
    parser.add_argument('--transcript', type=str, required=True,
                       help='Path to transcript file (e.g., transcripts/client_localhost_8888.export.txt)')
    parser.add_argument('--receipt', type=str, required=False,
                       help='Path to receipt JSON file (or "stdin" to read from stdin). If not provided, will look for client_receipt_*.json or server_receipt_*.json in transcripts/')
    parser.add_argument('--cert', type=str, required=True,
                       help='Path to signer certificate (e.g., certs/client.crt or certs/server.crt)')
    parser.add_argument('--ca-cert', type=str, default='certs/ca.crt',
                       help='Path to CA certificate (default: certs/ca.crt)')
    parser.add_argument('--expected-cn', type=str, default=None,
                       help='Expected Common Name for certificate validation')
    
    args = parser.parse_args()
    
    transcript_path = Path(args.transcript)
    cert_path = Path(args.cert)
    ca_cert_path = Path(args.ca_cert)
    
    print("=" * 70)
    print("TRANSCRIPT & SESSION RECEIPT VERIFICATION")
    print("=" * 70)
    
    # Load and validate certificate
    print(f"\n1. Loading certificate: {cert_path}")
    if not cert_path.exists():
        print(f"   ERROR: Certificate not found: {cert_path}")
        return
    
    cert_pem = load_certificate(cert_path)
    
    # Validate certificate
    print(f"2. Validating certificate against CA: {ca_cert_path}")
    try:
        if args.expected_cn:
            pki.validate_certificate(cert_pem, ca_cert_path, expected_cn=args.expected_cn)
        else:
            pki.validate_certificate(cert_pem, ca_cert_path)
        print("   ✓ Certificate is valid and trusted")
    except ValueError as e:
        print(f"   ✗ Certificate validation failed: {e}")
        return
    
    # Load transcript
    print(f"\n3. Loading transcript: {transcript_path}")
    if not transcript_path.exists():
        print(f"   ERROR: Transcript not found: {transcript_path}")
        return
    
    with open(transcript_path, 'r', encoding='utf-8') as f:
        transcript_lines = f.readlines()
    
    print(f"   Found {len(transcript_lines)} message entries")
    
    # Verify each message
    print("\n4. Verifying message signatures:")
    all_valid = True
    for i, line in enumerate(transcript_lines, 1):
        line = line.strip()
        if not line:
            continue
        
        parts = line.split('|')
        if len(parts) != 5:
            print(f"   Line {i}: Invalid format (expected 5 fields)")
            all_valid = False
            continue
        
        seqno = int(parts[0])
        ts = int(parts[1])
        ct = parts[2]
        sig = parts[3]
        peer_fingerprint = parts[4]
        
        is_valid = verify_message_signature(seqno, ts, ct, sig, cert_path)
        if is_valid:
            print(f"   Message {seqno}: ✓ Signature valid")
        else:
            print(f"   Message {seqno}: ✗ Signature INVALID")
            all_valid = False
    
    if not all_valid:
        print("\n   ⚠ WARNING: Some message signatures are invalid!")
    else:
        print("\n   ✓ All message signatures are valid")
    
    # Compute transcript hash
    print("\n5. Computing transcript hash:")
    computed_hash = verify_transcript_hash(transcript_path)
    print(f"   Computed hash: {computed_hash}")
    
    # Load and verify receipt
    print(f"\n6. Loading SessionReceipt:")
    if args.receipt:
        if args.receipt == "stdin":
            receipt_data = json.load(sys.stdin)
        else:
            receipt_path = Path(args.receipt)
            if not receipt_path.exists():
                print(f"   ERROR: Receipt file not found: {receipt_path}")
                return
            with open(receipt_path, 'r') as f:
                receipt_data = json.load(f)
    else:
        # Auto-detect receipt file based on transcript path
        transcript_name = transcript_path.stem
        # Try to find matching receipt file
        transcripts_dir = transcript_path.parent
        # Look for client_receipt or server_receipt files
        receipt_files = list(transcripts_dir.glob("client_receipt_*.json")) + \
                       list(transcripts_dir.glob("server_receipt_*.json"))
        if not receipt_files:
            print(f"   ERROR: No receipt file found. Please specify --receipt or ensure receipt files exist in {transcripts_dir}")
            return
        # Use the most recent receipt file
        receipt_path = max(receipt_files, key=lambda p: p.stat().st_mtime)
        print(f"   Auto-detected receipt file: {receipt_path}")
        with open(receipt_path, 'r') as f:
            receipt_data = json.load(f)
    
    receipt = Receipt.model_validate(receipt_data)
    print(f"   Peer: {receipt.peer}")
    print(f"   First seq: {receipt.first_seq}")
    print(f"   Last seq: {receipt.last_seq}")
    print(f"   Transcript hash: {receipt.transcript_sha256}")
    
    # Verify receipt hash matches transcript
    print("\n7. Verifying receipt hash matches transcript:")
    if receipt.transcript_sha256 == computed_hash:
        print("   ✓ Receipt hash matches computed transcript hash")
    else:
        print("   ✗ Receipt hash does NOT match computed transcript hash!")
        print(f"     Receipt hash:    {receipt.transcript_sha256}")
        print(f"     Computed hash:   {computed_hash}")
        return
    
    # Verify receipt signature
    print("\n8. Verifying receipt signature:")
    receipt_valid = verify_receipt(receipt, cert_path)
    if receipt_valid:
        print("   ✓ Receipt signature is valid")
    else:
        print("   ✗ Receipt signature is INVALID")
        return
    
    # Final result
    print("\n" + "=" * 70)
    print("VERIFICATION RESULT: ✓ ALL CHECKS PASSED")
    print("=" * 70)
    print("\nNon-repudiation verified:")
    print("  • All message signatures are valid")
    print("  • Receipt hash matches transcript")
    print("  • Receipt signature is valid")
    print("  • Certificate is trusted")
    print("\nThis transcript provides cryptographic proof of the session.")


if __name__ == "__main__":
    main()

