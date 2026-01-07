"""Create Root CA (RSA + self-signed X.509) using cryptography."""

import argparse
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta, timezone


def generate_ca(name: str, output_dir: Path = Path("certs")):
    """Generate Root CA keypair and self-signed certificate."""
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Generate RSA private key (2048 bits)
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    # Build self-signed certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureChat CA"),
    ])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.now(timezone.utc)
    ).not_valid_after(
        datetime.now(timezone.utc) + timedelta(days=3650)  # 10 years
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True
    ).add_extension(
        x509.KeyUsage(
            key_cert_sign=True,
            crl_sign=True,
            digital_signature=False,
            key_encipherment=False,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True
    ).sign(private_key, hashes.SHA256())
    
    # Save private key
    key_path = output_dir / "ca.key"
    with open(key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Save certificate
    cert_path = output_dir / "ca.crt"
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    print(f"Root CA generated successfully:")
    print(f"  Private key: {key_path}")
    print(f"  Certificate: {cert_path}")
    print(f"  CA Name: {name}")


def main():
    parser = argparse.ArgumentParser(description="Generate Root Certificate Authority")
    parser.add_argument("--name", required=True, help="Common Name for the CA")
    parser.add_argument("--out", default="certs", help="Output directory (default: certs)")
    args = parser.parse_args()
    
    generate_ca(args.name, Path(args.out))


if __name__ == "__main__":
    main()
