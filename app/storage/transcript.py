"""Append-only transcript logging and transcript hash computation for non-repudiation."""

from pathlib import Path
from typing import Optional
from app.common.utils import sha256_hex


class TranscriptLogger:
    """Append-only transcript logger for session messages."""
    
    def __init__(self, transcript_path: Path):
        """
        Initialize transcript logger.
        
        Args:
            transcript_path: Path to transcript file
        """
        self.transcript_path = transcript_path
        self.transcript_path.parent.mkdir(parents=True, exist_ok=True)
        self.lines = []
    
    def append(self, seqno: int, ts: int, ct: str, sig: str, peer_cert_fingerprint: str):
        """
        Append message entry to transcript.
        
        Args:
            seqno: Sequence number
            ts: Timestamp in milliseconds
            ct: Base64 encoded ciphertext
            sig: Base64 encoded signature
            peer_cert_fingerprint: SHA-256 fingerprint of peer certificate (hex)
        """
        line = f"{seqno}|{ts}|{ct}|{sig}|{peer_cert_fingerprint}\n"
        self.lines.append(line)
        
        # Append to file
        with open(self.transcript_path, "a", encoding="utf-8") as f:
            f.write(line)
    
    def compute_hash(self) -> str:
        """
        Compute SHA-256 hash of entire transcript.
        
        Returns:
            Hex string of transcript hash (64 characters)
        """
        # Read all lines from file
        if not self.transcript_path.exists():
            return sha256_hex(b"")
        
        with open(self.transcript_path, "r", encoding="utf-8") as f:
            content = f.read()
        
        # Compute hash of concatenated lines
        return sha256_hex(content.encode('utf-8'))
    
    def get_first_seq(self) -> Optional[int]:
        """Get first sequence number from transcript."""
        if not self.transcript_path.exists():
            return None
        
        with open(self.transcript_path, "r", encoding="utf-8") as f:
            first_line = f.readline()
            if first_line:
                return int(first_line.split('|')[0])
        return None
    
    def get_last_seq(self) -> Optional[int]:
        """Get last sequence number from transcript."""
        if not self.transcript_path.exists():
            return None
        
        with open(self.transcript_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
            if lines:
                last_line = lines[-1]
                return int(last_line.split('|')[0])
        return None
    
    def export(self, output_path: Optional[Path] = None) -> Path:
        """
        Export transcript to file.
        
        Args:
            output_path: Optional output path (default: transcript_path with .export suffix)
        
        Returns:
            Path to exported transcript file
        """
        if output_path is None:
            output_path = self.transcript_path.with_suffix('.export.txt')
        
        # Copy transcript to export location
        if self.transcript_path.exists():
            with open(self.transcript_path, "r", encoding="utf-8") as src:
                with open(output_path, "w", encoding="utf-8") as dst:
                    dst.write(src.read())
        
        return output_path


def get_cert_fingerprint(cert_pem: str) -> str:
    """
    Compute SHA-256 fingerprint of certificate.
    
    Args:
        cert_pem: PEM encoded certificate string
    
    Returns:
        Hex string fingerprint (64 characters)
    """
    cert_bytes = cert_pem.encode('utf-8')
    return sha256_hex(cert_bytes)
