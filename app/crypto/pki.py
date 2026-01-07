"""X.509 certificate validation: CA signature, validity window, CN/SAN matching."""

from pathlib import Path
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import NameOID, ExtensionOID, SignatureAlgorithmOID


def validate_certificate(
    cert_pem: str,
    ca_cert_path: Path,
    expected_cn: str = None
) -> x509.Certificate:
    """
    Validate X.509 certificate against trusted CA.
    
    Args:
        cert_pem: PEM encoded certificate string
        ca_cert_path: Path to trusted CA certificate
        expected_cn: Expected Common Name (optional, for CN/SAN matching)
    
    Returns:
        Validated certificate object
    
    Raises:
        ValueError: With BAD_CERT message if validation fails
    """
    # Load peer certificate
    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode('utf-8'))
    except Exception as e:
        raise ValueError(f"BAD_CERT: Invalid certificate format - {e}")
    
    # Load CA certificate
    try:
        with open(ca_cert_path, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())
    except Exception as e:
        raise ValueError(f"BAD_CERT: Failed to load CA certificate - {e}")
    
    # Verify issuer matches CA
    if cert.issuer != ca_cert.subject:
        raise ValueError("BAD_CERT: Certificate not signed by trusted CA")
    
    # Check if self-signed (not from our CA)
    if cert.issuer == cert.subject:
        raise ValueError("BAD_CERT: Self-signed certificate rejected")
    
    # Verify CA signature
    try:
        ca_public_key = ca_cert.public_key()
        # Determine hash algorithm from certificate signature algorithm
        sig_alg = cert.signature_algorithm_oid
        if sig_alg == SignatureAlgorithmOID.RSA_WITH_SHA256:
            hash_alg = hashes.SHA256()
        elif sig_alg == SignatureAlgorithmOID.RSA_WITH_SHA384:
            hash_alg = hashes.SHA384()
        elif sig_alg == SignatureAlgorithmOID.RSA_WITH_SHA512:
            hash_alg = hashes.SHA512()
        else:
            hash_alg = hashes.SHA256()  # Default
        
        ca_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            hash_alg
        )
    except Exception as e:
        raise ValueError(f"BAD_CERT: Certificate signature verification failed - {e}")
    
    # Verify validity window
    now = datetime.now(timezone.utc)
    if cert.not_valid_before_utc > now:
        raise ValueError("BAD_CERT: Certificate not yet valid")
    if cert.not_valid_after_utc < now:
        raise ValueError("BAD_CERT: Certificate expired")
    
    # Verify CN/SAN if expected_cn provided
    if expected_cn:
        cert_cn = None
        cert_sans = []
        
        # Extract CN from subject
        try:
            cn_attr = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            if cn_attr:
                cert_cn = cn_attr[0].value
        except Exception:
            pass
        
        # Extract DNS names from SAN extension
        try:
            san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            if san_ext:
                cert_sans = [name.value for name in san_ext.value if isinstance(name, x509.DNSName)]
        except x509.ExtensionNotFound:
            pass
        
        # Check if expected_cn matches CN or any SAN
        if cert_cn != expected_cn and expected_cn not in cert_sans:
            raise ValueError(f"BAD_CERT: CN/SAN mismatch - expected '{expected_cn}', got CN='{cert_cn}', SAN={cert_sans}")
    
    return cert
