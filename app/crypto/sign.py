"""RSA PKCS#1 v1.5 SHA-256 sign/verify functions."""

from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography import x509
from app.common.utils import b64e, b64d


def sign(data: bytes, private_key_path: Path) -> str:
    """
    Sign data using RSA PKCS#1 v1.5 with SHA-256.
    
    Args:
        data: Data bytes to sign
        private_key_path: Path to PEM encoded RSA private key
    
    Returns:
        Base64 encoded signature string
    """
    # Load private key
    with open(private_key_path, "rb") as f:
        private_key = load_pem_private_key(f.read(), password=None)
    
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise ValueError("Private key must be RSA")
    
    # Compute SHA-256 hash
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    hash_value = digest.finalize()
    
    # Sign hash with RSA PKCS#1 v1.5
    signature = private_key.sign(
        hash_value,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    
    return b64e(signature)


def verify(data: bytes, signature_b64: str, cert_path: Path) -> bool:
    """
    Verify RSA PKCS#1 v1.5 SHA-256 signature.
    
    Args:
        data: Original data bytes
        signature_b64: Base64 encoded signature string
        cert_path: Path to PEM encoded certificate containing public key
    
    Returns:
        True if signature is valid, False otherwise
    
    Raises:
        ValueError: With SIG_FAIL message if verification fails
    """
    # Load certificate and extract public key
    with open(cert_path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
    
    public_key = cert.public_key()
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise ValueError("Certificate must contain RSA public key")
    
    # Decode signature
    try:
        signature = b64d(signature_b64)
    except Exception as e:
        raise ValueError(f"SIG_FAIL: Invalid signature encoding - {e}")
    
    # Compute SHA-256 hash
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    hash_value = digest.finalize()
    
    # Verify signature
    try:
        public_key.verify(
            signature,
            hash_value,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception:
        raise ValueError("SIG_FAIL: Signature verification failed")
