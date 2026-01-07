"""AES-128 ECB mode encryption/decryption with PKCS#7 padding."""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend
from app.common.utils import b64e, b64d


def encrypt(plaintext: bytes, key: bytes) -> str:
    """
    Encrypt plaintext using AES-128 ECB mode with PKCS#7 padding.
    
    Args:
        plaintext: Data bytes to encrypt
        key: 16-byte AES key
    
    Returns:
        Base64 encoded ciphertext string
    
    Raises:
        ValueError: If key length is not 16 bytes
    """
    if len(key) != 16:
        raise ValueError("AES key must be exactly 16 bytes")
    
    # Apply PKCS#7 padding
    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    
    # Create AES cipher in ECB mode
    cipher = Cipher(
        algorithms.AES(key),
        modes.ECB(),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    
    # Encrypt
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    return b64e(ciphertext)


def decrypt(ciphertext_b64: str, key: bytes) -> bytes:
    """
    Decrypt ciphertext using AES-128 ECB mode and remove PKCS#7 padding.
    
    Args:
        ciphertext_b64: Base64 encoded ciphertext string
        key: 16-byte AES key
    
    Returns:
        Decrypted plaintext bytes
    
    Raises:
        ValueError: If key length is not 16 bytes or decryption fails
    """
    if len(key) != 16:
        raise ValueError("AES key must be exactly 16 bytes")
    
    # Decode base64
    try:
        ciphertext = b64d(ciphertext_b64)
    except Exception as e:
        raise ValueError(f"Invalid ciphertext encoding - {e}")
    
    # Create AES cipher in ECB mode
    cipher = Cipher(
        algorithms.AES(key),
        modes.ECB(),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    
    # Decrypt
    try:
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    except Exception as e:
        raise ValueError(f"Decryption failed - {e}")
    
    # Remove PKCS#7 padding
    unpadder = sym_padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    
    return plaintext
