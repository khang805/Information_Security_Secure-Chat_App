"""Generate invalid self-signed certificate for testing BAD_CERT rejection."""

import argparse
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta, timezone


def generate_invalid_cert(name: str, output_dir: Path = Path("certs")):
    """Generate self-signed certificate (not from trusted CA) for testing."""
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Generate RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    # Build self-signed certificate (not from our CA)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, name),
    ])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer  # Self-signed, not from our CA
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.now(timezone.utc)
    ).not_valid_after(
        datetime.now(timezone.utc) + timedelta(days=365)
    ).sign(private_key, hashes.SHA256())
    
    # Save private key
    key_path = output_dir / "invalid.key"
    with open(key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Save certificate
    cert_path = output_dir / "invalid.crt"
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    print(f"Invalid self-signed certificate generated:")
    print(f"  Private key: {key_path}")
    print(f"  Certificate: {cert_path}")
    print(f"  Note: This certificate is NOT signed by your CA and should be rejected")


def main():
    parser = argparse.ArgumentParser(description="Generate invalid certificate for testing")
    parser.add_argument("--name", default="invalid.local", help="Common Name for invalid cert")
    parser.add_argument("--out", default="certs", help="Output directory")
    args = parser.parse_args()
    
    generate_invalid_cert(args.name, Path(args.out))


if __name__ == "__main__":
    main()

