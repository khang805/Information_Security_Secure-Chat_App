"""MySQL users table + salted hashing (no chat storage)."""

import argparse
import os
import secrets
import hashlib
from typing import Optional
import pymysql
from dotenv import load_dotenv

load_dotenv()


def get_db_connection():
    """Get MySQL database connection from environment variables."""
    return pymysql.connect(
        host=os.getenv('DB_HOST', 'localhost'),
        port=int(os.getenv('DB_PORT', 3307)),
        user=os.getenv('DB_USER', 'user'),
        password=os.getenv('DB_PASSWORD', '12345678'),
        database=os.getenv('DB_NAME', 'securechat'),
        cursorclass=pymysql.cursors.DictCursor
    )


def init_database():
    """Initialize database and create users table."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    email VARCHAR(255) NOT NULL,
                    username VARCHAR(255) NOT NULL UNIQUE,
                    salt VARBINARY(16) NOT NULL,
                    pwd_hash CHAR(64) NOT NULL,
                    PRIMARY KEY (email),
                    INDEX idx_username (username)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """)
        conn.commit()
        print("Database initialized successfully.")
    finally:
        conn.close()


def register_user(email: str, username: str, password: str) -> bool:
    """
    Register a new user with salted password hash.
    
    Args:
        email: User email address
        username: Unique username
        password: Plaintext password
    
    Returns:
        True if registration successful, False if user already exists
    
    Raises:
        ValueError: If username is already taken
    """
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # Check if username already exists
            cursor.execute("SELECT username FROM users WHERE username = %s", (username,))
            if cursor.fetchone():
                raise ValueError(f"Username '{username}' already exists")
            
            # Check if email already exists
            cursor.execute("SELECT email FROM users WHERE email = %s", (email,))
            if cursor.fetchone():
                raise ValueError(f"Email '{email}' already registered")
            
            # Generate random 16-byte salt
            salt = secrets.token_bytes(16)
            
            # Compute password hash: hex(SHA256(salt || password))
            pwd_hash = hashlib.sha256(salt + password.encode('utf-8')).hexdigest()
            
            # Insert user
            cursor.execute(
                "INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s, %s, %s, %s)",
                (email, username, salt, pwd_hash)
            )
        conn.commit()
        return True
    except pymysql.IntegrityError as e:
        conn.rollback()
        raise ValueError(f"Registration failed: {e}")
    finally:
        conn.close()


def verify_login(email: str, password_hash_hex: str, salt: bytes) -> bool:
    """
    Verify user login with constant-time comparison.
    
    Args:
        email: User email address
        password_hash_hex: Hex string of SHA256(salt||password) from client
        salt: Salt bytes used for hashing
    
    Returns:
        True if login successful, False otherwise
    """
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT pwd_hash FROM users WHERE email = %s",
                (email,)
            )
            result = cursor.fetchone()
            if not result:
                return False
            
            stored_hash = result['pwd_hash']
            
            # Constant-time comparison
            if len(password_hash_hex) != len(stored_hash):
                return False
            
            # Use secrets.compare_digest for constant-time comparison
            return secrets.compare_digest(password_hash_hex, stored_hash)
    finally:
        conn.close()


def get_user_salt(email: str) -> Optional[bytes]:
    """
    Get salt for a user by email.
    
    Args:
        email: User email address
    
    Returns:
        Salt bytes if user exists, None otherwise
    """
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT salt FROM users WHERE email = %s", (email,))
            result = cursor.fetchone()
            if result:
                return result['salt']
            return None
    finally:
        conn.close()


def main():
    parser = argparse.ArgumentParser(description="Database management")
    parser.add_argument("--init", action="store_true", help="Initialize database tables")
    args = parser.parse_args()
    
    if args.init:
        init_database()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
