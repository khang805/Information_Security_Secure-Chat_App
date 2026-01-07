"""Issue server/client cert signed by Root CA (SAN=DNSName(CN))."""

import argparse
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from datetime import datetime, timedelta, timezone


def issue_certificate(
    cn: str,
    output_prefix: str,
    ca_cert_path: Path,
    ca_key_path: Path,
    output_dir: Path = Path("certs")
):
    """Issue X.509 certificate signed by Root CA."""
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Load CA certificate and private key
    with open(ca_cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    
    with open(ca_key_path, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)
    
    # Generate RSA private key for entity (2048 bits)
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    # Build certificate
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])
    
    cert_builder = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.now(timezone.utc)
    ).not_valid_after(
        datetime.now(timezone.utc) + timedelta(days=365)  # 1 year
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName(cn)
        ]),
        critical=False
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_encipherment=True,
            key_cert_sign=False,
            crl_sign=False,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True
    ).add_extension(
        x509.ExtendedKeyUsage([
            ExtendedKeyUsageOID.SERVER_AUTH,
            ExtendedKeyUsageOID.CLIENT_AUTH
        ]),
        critical=False
    )
    
    cert = cert_builder.sign(ca_key, hashes.SHA256())
    
    # Save private key
    key_path = output_dir / f"{output_prefix}.key"
    with open(key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Save certificate
    cert_path = output_dir / f"{output_prefix}.crt"
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    print(f"Certificate issued successfully:")
    print(f"  Common Name: {cn}")
    print(f"  Private key: {key_path}")
    print(f"  Certificate: {cert_path}")
    print(f"  Signed by: {ca_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value}")


def main():
    parser = argparse.ArgumentParser(description="Issue certificate signed by Root CA")
    parser.add_argument("--cn", required=True, help="Common Name (hostname) for the certificate")
    parser.add_argument("--out", help="Output file prefix (default: CN)")
    parser.add_argument("--ca-cert", default="certs/ca.crt", help="Path to CA certificate")
    parser.add_argument("--ca-key", default="certs/ca.key", help="Path to CA private key")
    parser.add_argument("--dir", default="certs", help="Output directory (default: certs)")
    args = parser.parse_args()
    
    # Extract just the filename from --out if it contains path separators
    if args.out:
        output_prefix = Path(args.out).stem  # Get filename without extension
    else:
        output_prefix = args.cn.split('.')[0]
    
    issue_certificate(
        cn=args.cn,
        output_prefix=output_prefix,
        ca_cert_path=Path(args.ca_cert),
        ca_key_path=Path(args.ca_key),
        output_dir=Path(args.dir)
    )


if __name__ == "__main__":
    main()
