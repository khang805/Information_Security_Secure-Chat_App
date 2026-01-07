"""Classic Diffie-Hellman key exchange and session key derivation."""

import secrets
import hashlib


# Standard DH parameters (RFC 5114, 2048-bit MODP Group)
# Using smaller but secure parameters for practical use
DEFAULT_P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF

DEFAULT_G = 2


def generate_private_key() -> int:
    """Generate random private key for DH exchange."""
    return secrets.randbits(256)  # 256-bit private key


def compute_public_value(g: int, p: int, private_key: int) -> int:
    """
    Compute public value: A = g^a mod p (client) or B = g^b mod p (server).
    
    Args:
        g: Generator/base
        p: Prime modulus
        private_key: Private exponent (a or b)
    
    Returns:
        Public value (A or B)
    """
    return pow(g, private_key, p)


def compute_shared_secret(peer_public: int, private_key: int, p: int) -> int:
    """
    Compute shared secret: Ks = peer_public^private_key mod p.
    
    Args:
        peer_public: Peer's public value (B for client, A for server)
        private_key: Own private exponent (a for client, b for server)
        p: Prime modulus
    
    Returns:
        Shared secret Ks
    """
    return pow(peer_public, private_key, p)


def derive_key(shared_secret: int) -> bytes:
    """
    Derive 16-byte AES key from shared secret: K = Trunc16(SHA256(big-endian(Ks))).
    
    Args:
        shared_secret: Shared secret Ks from DH exchange
    
    Returns:
        16-byte AES key
    """
    # Convert shared secret to big-endian bytes
    ks_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, byteorder='big')
    
    # Compute SHA-256 hash
    hash_value = hashlib.sha256(ks_bytes).digest()
    
    # Truncate to 16 bytes (first 16 bytes)
    return hash_value[:16]
