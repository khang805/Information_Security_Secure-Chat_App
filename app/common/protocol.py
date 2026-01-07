"""Pydantic models for secure chat protocol messages."""

from pydantic import BaseModel, Field
from typing import Literal


class Hello(BaseModel):
    """Client certificate exchange message."""
    type: Literal["hello"] = "hello"
    client_cert: str = Field(..., description="PEM encoded client certificate")
    nonce: str = Field(..., description="Base64 encoded random nonce")


class ServerHello(BaseModel):
    """Server certificate exchange message."""
    type: Literal["server_hello"] = "server_hello"
    server_cert: str = Field(..., description="PEM encoded server certificate")
    nonce: str = Field(..., description="Base64 encoded random nonce")


class Register(BaseModel):
    """User registration message (encrypted under temporary AES key)."""
    type: Literal["register"] = "register"
    email: str
    username: str
    pwd: str = Field(..., description="Base64 encoded SHA256(salt||password)")
    salt: str = Field(..., description="Base64 encoded 16-byte salt")


class Login(BaseModel):
    """User authentication message (encrypted under temporary AES key)."""
    type: Literal["login"] = "login"
    email: str
    pwd: str = Field(..., description="Base64 encoded SHA256(salt||password)")
    nonce: str = Field(..., description="Base64 encoded random nonce")


class DHClient(BaseModel):
    """Client Diffie-Hellman key exchange parameters."""
    type: Literal["dh_client"] = "dh_client"
    g: int = Field(..., description="Generator/base")
    p: int = Field(..., description="Prime modulus")
    A: int = Field(..., description="Client public value g^a mod p")


class DHServer(BaseModel):
    """Server Diffie-Hellman key exchange response."""
    type: Literal["dh_server"] = "dh_server"
    B: int = Field(..., description="Server public value g^b mod p")


class Msg(BaseModel):
    """Encrypted chat message with signature."""
    type: Literal["msg"] = "msg"
    seqno: int = Field(..., description="Sequence number for replay protection")
    ts: int = Field(..., description="Unix timestamp in milliseconds")
    ct: str = Field(..., description="Base64 encoded AES-128 ciphertext")
    sig: str = Field(..., description="Base64 encoded RSA signature over SHA256(seqno||ts||ct)")


class Receipt(BaseModel):
    """Signed session receipt for non-repudiation."""
    type: Literal["receipt"] = "receipt"
    peer: Literal["client", "server"] = Field(..., description="Sender identity")
    first_seq: int = Field(..., description="First sequence number in session")
    last_seq: int = Field(..., description="Last sequence number in session")
    transcript_sha256: str = Field(..., description="SHA256 hash of transcript (64 hex chars)")
    sig: str = Field(..., description="Base64 encoded RSA signature over transcript hash")
