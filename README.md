# SecureChat – Assignment #2 (CS-3002 Information Security, Fall 2025)

This repository implements a **console-based, PKI-enabled Secure Chat System** in **Python**, demonstrating how cryptographic primitives combine to achieve:

**Confidentiality, Integrity, Authenticity, and Non-Repudiation (CIANR)**.

## 🧩 Overview

This secure chat system implements a complete application-layer security protocol using:
- **AES-128 (ECB)** for symmetric encryption (confidentiality)
- **RSA PKCS#1 v1.5 SHA-256** for digital signatures (integrity & authenticity)
- **X.509 Certificates** with PKI for identity verification
- **Diffie-Hellman Key Exchange** for secure session key establishment
- **SHA-256** for password hashing and transcript integrity
- **MySQL Database** for secure user credential storage

All cryptographic operations are implemented at the application layer (no TLS/SSL).

## 🏗️ Folder Structure

```
securechat-skeleton/
├─ app/
│  ├─ client.py              # Client workflow (plain TCP, no TLS)
│  ├─ server.py              # Server workflow (plain TCP, no TLS)
│  ├─ crypto/
│  │  ├─ aes.py              # AES-128(ECB)+PKCS#7 encryption/decryption
│  │  ├─ dh.py               # Classic DH key exchange + key derivation
│  │  ├─ pki.py              # X.509 certificate validation
│  │  └─ sign.py              # RSA SHA-256 sign/verify (PKCS#1 v1.5)
│  ├─ common/
│  │  ├─ protocol.py         # Pydantic message models
│  │  └─ utils.py            # Helper functions (base64, timestamps, hashing)
│  └─ storage/
│     ├─ db.py               # MySQL user store (salted SHA-256 passwords)
│     └─ transcript.py       # Append-only transcript + transcript hash
├─ scripts/
│  ├─ gen_ca.py              # Create Root CA (RSA + self-signed X.509)
│  ├─ gen_cert.py            # Issue client/server certs signed by Root CA
│  └─ gen_invalid_cert.py    # Generate invalid cert for testing
├─ tests/
│  ├─ tamper_test.py         # Test message tampering (SIG_FAIL)
│  ├─ replay_test.py         # Test replay protection (REPLAY)
│  └─ verify_transcript.py   # Offline transcript verification
├─ certs/                    # Certificate storage (gitignored)
├─ transcripts/              # Session transcripts (gitignored)
├─ .env.example              # Environment configuration template
├─ .gitignore                # Ignores secrets, certs, keys, logs
└─ requirements.txt          # Python dependencies
```

## ⚙️ Complete Setup Instructions

### Prerequisites

- **Python 3.8+** installed
- **Docker** installed (for MySQL and Adminer)
- **Git** installed

### Step 1: Clone and Setup Python Environment

```bash
# Clone the repository (or use your fork)
git clone <your-repo-url>
cd securechat-skeleton-main

# Create virtual environment
python -m venv .venv

# Activate virtual environment
.venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Step 2: Configure Environment Variables

```bash
# Copy the example environment file
copy .env.example .env
```

**Edit `.env` file** with your configuration (defaults are provided):

```env
# Database Configuration
DB_HOST=localhost
DB_PORT=3307
DB_USER=user
DB_PASSWORD=12345678
DB_NAME=securechat

# Server Configuration
SERVER_HOST=localhost
SERVER_PORT=8888

# Certificate Paths (relative to project root)
CA_CERT_PATH=certs/ca.crt
SERVER_CERT_PATH=certs/server.crt
SERVER_KEY_PATH=certs/server.key
CLIENT_CERT_PATH=certs/client.crt
CLIENT_KEY_PATH=certs/client.key
```

**Note:** The `.env` file is gitignored. Never commit it with real credentials.

### Step 3: Setup MySQL Database with Docker

This project uses a **separate MySQL container** on port **3307** to avoid conflicts with existing MySQL installations.

#### 3.1: Create MySQL Container

```bash
docker run -d --name securechat-db -e MYSQL_ROOT_PASSWORD=rootpass -e MYSQL_DATABASE=securechat -e MYSQL_USER=user -e MYSQL_PASSWORD=12345678 -p 3307:3306 mysql:8
```

**Explanation:**
- `--name securechat-db`: Container name
- `-e MYSQL_ROOT_PASSWORD`: Root password
- `-e MYSQL_DATABASE`: Database name (must match `DB_NAME` in `.env`)
- `-e MYSQL_USER`: Database user (must match `DB_USER` in `.env`)
- `-e MYSQL_PASSWORD`: User password (must match `DB_PASSWORD` in `.env`)
- `-p 3307:3306`: Maps container port 3306 to host port 3307

#### 3.2: Verify MySQL Container is Running

```bash
docker ps
```

You should see `securechat-db` container running.

#### 3.3: Initialize Database Tables

```bash
python -m app.storage.db --init
```

**Expected Output:**
```
Database initialized successfully.
```

### Step 4: Setup Adminer (Database Management UI)

Adminer provides a web interface to manage the MySQL database.

#### 4.1: Create Adminer Container

```bash
docker run -d --name securechat-adminer --link securechat-db:db -p 8081:8080 adminer
```

**Explanation:**
- `--name securechat-adminer`: Container name
- `--link securechat-db:db`: Links to MySQL container
- `-p 8081:8080`: Maps container port 8080 to host port 8081

#### 4.2: Access Adminer

1. Open browser: `http://localhost:8081`
2. **Login credentials:**
   - **System:** MySQL
   - **Server:** `db` (use the linked container name)
   - **Username:** `user`
   - **Password:** `12345678`
   - **Database:** `securechat`

#### 4.3: Verify Database

After logging in, you should see the `users` table with columns:
- `email` (VARCHAR)
- `username` (VARCHAR, UNIQUE)
- `salt` (VARBINARY)
- `pwd_hash` (CHAR(64))

### Step 5: Generate Certificates

The PKI system requires a Root CA and client/server certificates.

#### 5.1: Generate Root Certificate Authority (CA)

```bash
python scripts/gen_ca.py --name "FAST-NU Root CA"
```

**Expected Output:**
```
Root CA generated:
  Private key: certs/ca.key
  Certificate: certs/ca.crt
  Subject: CN=FAST-NU Root CA
```

#### 5.2: Generate Server Certificate

```bash
python scripts/gen_cert.py --cn server.local --out certs/server
```

**Expected Output:**
```
Certificate issued:
  Private key: certs/server.key
  Certificate: certs/server.crt
  Subject: CN=server.local
  Signed by: FAST-NU Root CA
```

#### 5.3: Generate Client Certificate

```bash
python scripts/gen_cert.py --cn client.local --out certs/client
```

**Expected Output:**
```
Certificate issued:
  Private key: certs/client.key
  Certificate: certs/client.crt
  Subject: CN=client.local
  Signed by: FAST-NU Root CA
```

#### 5.4: Verify Certificates

```bash
# View CA certificate
openssl x509 -in certs/ca.crt -text -noout

# View server certificate
openssl x509 -in certs/server.crt -text -noout

# View client certificate
openssl x509 -in certs/client.crt -text -noout
```

**Important:** All certificates should show:
- Valid issuer (CA for server/client, self-signed for CA)
- Valid date range
- Common Name (CN) matching expected values

### Step 6: Verify Setup

Check that all files exist:

```bash
# Check certificates
dir certs\*.crt certs\*.key

# Should see:
# - certs/ca.crt, certs/ca.key
# - certs/server.crt, certs/server.key
# - certs/client.crt, certs/client.key
```

## 🚀 Running the Application

### Start the Server

**Terminal 1:**
```bash
# Activate virtual environment (if not already active)
.venv\Scripts\activate

# Start server
python -m app.server
```

**Expected Output:**
```
Server listening on localhost:8888
```

### Start the Client

**Terminal 2:**
```bash
# Activate virtual environment (if not already active)
.venv\Scripts\activate

# Start client
python -m app.client
```

**Expected Output:**
```
Connected to server at localhost:8888
Server certificate validated
```

### Register a New User

When prompted:
```
Choose an option:
1. Register
2. Login
Enter choice: 1
Email: test@example.com
Username: testuser
Password: mypassword123
```

**Expected Output:**
```
Registration successful!
```

### Login

When prompted:
```
Choose an option:
1. Register
2. Login
Enter choice: 2
Email: test@example.com
Password: mypassword123
```

**Expected Output:**
```
Login successful!
Session established! Type messages (or 'quit' to exit):
```

### Send Messages

After successful login:
```
> Hello, this is a test message
Server acknowledged: received

> Another message
Server acknowledged: received

> quit
```

**Expected Output:**
```
Client receipt saved to: transcripts/client_receipt_localhost_8888.json
Transcript exported to: transcripts/client_localhost_8888.export.txt
Session completed. All files saved in transcripts/ directory.
```

## 🧪 Running Tests

All test scripts are located in the `tests/` directory.

### Test 1: Tamper Test (SIG_FAIL)

Tests that message tampering is detected via signature verification failure.

**Terminal 1:**
```bash
python -m app.server
```

**Terminal 2:**
```bash
python -m tests.tamper_test
```

**When prompted:**
- Enter your registered email
- Enter your password

**Expected Output:**
```
=== TAMPER TEST ===
Performing login...
Login successful!
Session key established

1. Sending normal (valid) message...
   Success: received

2. Sending TAMPERED message (flipped bit in ciphertext)...
   ✓ TAMPER DETECTED: SIG_FAIL: Signature verification failed
   ✓ Signature verification failed as expected!
```

**Evidence:** Screenshot showing `SIG_FAIL` error.

### Test 2: Replay Test (REPLAY)

Tests that replay attacks are prevented via sequence number checking.

**Terminal 1:**
```bash
python -m app.server
```

**Terminal 2:**
```bash
python -m tests.replay_test
```

**When prompted:**
- Enter your registered email
- Enter your password

**Expected Output:**
```
=== REPLAY TEST ===
Performing login...
Login successful!
Session key established

1. Sending first message (seqno=1)...
   Success: received

2. Sending second message (seqno=2) - valid...
   Success: received

3. REPLAY ATTACK: Resending message with seqno=1 (already used)...
   ✓ REPLAY DETECTED: REPLAY: Sequence number 1 already seen
   ✓ Replay protection works as expected!
```

**Evidence:** Screenshot showing `REPLAY` error.

### Test 3: Invalid Certificate Test (BAD_CERT)

Tests that invalid/self-signed certificates are rejected.

**Step 1: Generate Invalid Certificate**
```bash
python scripts/gen_invalid_cert.py
```

**Step 2: Backup Valid Certificates**
```bash
copy certs\client.crt certs\client.crt.backup
copy certs\client.key certs\client.key.backup
```

**Step 3: Replace with Invalid Certificate**
```bash
copy certs\invalid.crt certs\client.crt
copy certs\invalid.key certs\client.key
```

**Step 4: Start Server**
```bash
python -m app.server
```

**Step 5: Try to Connect**
```bash
python -m app.client
```

**Expected Output:**
```
Connected to server at localhost:8888
Error: BAD_CERT: Self-signed certificate rejected
```

**Step 6: Restore Valid Certificates**
```bash
copy certs\client.crt.backup certs\client.crt
copy certs\client.key.backup certs\client.key
```

**Evidence:** Screenshot showing `BAD_CERT` error.

### Test 4: Non-Repudiation Verification

Tests offline verification of transcript and SessionReceipt.

**Step 1: Run a Chat Session**

**Terminal 1:**
```bash
python -m app.server
```

**Terminal 2:**
```bash
python -m app.client
```

- Login with your credentials
- Send 2-3 messages
- Type `quit` to end session

**Step 2: Verify Transcript and Receipt**

```bash
python -m tests.verify_transcript \
  --transcript transcripts/client_localhost_8888.export.txt \
  --cert certs/client.crt \
  --expected-cn client.local
```

**Expected Output:**
```
======================================================================
TRANSCRIPT & SESSION RECEIPT VERIFICATION
======================================================================

1. Loading certificate: certs/client.crt
2. Validating certificate against CA: certs/ca.crt
   ✓ Certificate is valid and trusted

3. Loading transcript: transcripts/client_localhost_8888.export.txt
   Found 3 message entries

4. Verifying message signatures:
   Message 1: ✓ Signature valid
   Message 2: ✓ Signature valid
   Message 3: ✓ Signature valid

   ✓ All message signatures are valid

5. Computing transcript hash:
   Computed hash: abc123def456...

6. Loading SessionReceipt:
   Auto-detected receipt file: transcripts/client_receipt_localhost_8888.json
   Peer: client
   First seq: 1
   Last seq: 3
   Transcript hash: abc123def456...

7. Verifying receipt hash matches transcript:
   ✓ Receipt hash matches computed transcript hash

8. Verifying receipt signature:
   ✓ Receipt signature is valid

======================================================================
VERIFICATION RESULT: ✓ ALL CHECKS PASSED
======================================================================
```

**Step 3: Test Tampering Detection**

Edit the transcript file (change any character), then run verification again:

```bash
# Edit transcript file (add/remove a character)
# Then verify again
python -m tests.verify_transcript \
  --transcript transcripts/client_localhost_8888.export.txt \
  --cert certs/client.crt \
  --expected-cn client.local
```

**Expected Output:**
```
7. Verifying receipt hash matches transcript:
   ✗ Receipt hash does NOT match computed transcript hash!
     Receipt hash:    abc123def456...
     Computed hash:   xyz789ghi012...
```

**Evidence:** Screenshots showing successful verification and tampering detection.

### Test 5: Wireshark Capture

Captures network traffic to verify encrypted payloads (no plaintext).

**Step 1: Start Wireshark**

1. Open Wireshark
2. Select loopback interface (`Loopback: lo0` on Mac, `Npcap Loopback Adapter` on Windows)
3. Start capture

**Step 2: Run Chat Session**

**Terminal 1:**
```bash
python -m app.server
```

**Terminal 2:**
```bash
python -m app.client
```

- Login and send messages
- Type `quit` to end

**Step 3: Stop Capture and Analyze**

1. Stop Wireshark capture
2. Apply filter: `tcp.port == 8888`
3. Look for TCP packets with data
4. Expand packet → TCP → Data
5. Verify payload is encrypted (base64 encoded, no readable plaintext)

**Evidence:** Screenshot showing encrypted payload in Wireshark.

## 📋 Test Evidence Checklist

- [x] **Wireshark Capture:** Encrypted payloads only (no plaintext visible)
- [x] **Invalid Certificate:** Self-signed cert rejected with `BAD_CERT` error
- [x] **Tamper Test:** Modified ciphertext causes `SIG_FAIL` error
- [x] **Replay Test:** Duplicate sequence number causes `REPLAY` error
- [x] **Non-Repudiation:** Transcript and SessionReceipt verified offline

## 🔧 Troubleshooting

### MySQL Connection Issues

**Problem:** `Access denied for user 'user'@'localhost'`

**Solution:**
1. Verify MySQL container is running: `docker ps`
2. Check `.env` file has correct credentials
3. Verify port 3307 is not in use: `netstat -an | findstr 3307`

**Problem:** `Can't connect to MySQL server`

**Solution:**
1. Restart MySQL container: `docker restart securechat-db`
2. Wait 10-15 seconds for MySQL to initialize
3. Try again

### Certificate Issues

**Problem:** `BAD_CERT: Certificate not signed by trusted CA`

**Solution:**
1. Regenerate certificates:
   ```bash
   python scripts/gen_ca.py --name "FAST-NU Root CA"
   python scripts/gen_cert.py --cn server.local --out certs/server
   python scripts/gen_cert.py --cn client.local --out certs/client
   ```

**Problem:** `Certificate validation failed: can't compare offset-naive and offset-aware datetimes`

**Solution:**
1. Regenerate all certificates (this was fixed in the code)
2. Delete old certificates: `del certs\*.crt certs\*.key`
3. Regenerate: Follow Step 5 above

### Port Already in Use

**Problem:** `Address already in use` (port 8888)

**Solution:**
1. Change `SERVER_PORT` in `.env` to a different port (e.g., 8889)
2. Update both server and client `.env` files
3. Restart server and client

## 🚫 Important Rules

- **Do not use TLS/SSL or any secure-channel abstraction**  
  (e.g., `ssl`, HTTPS, WSS, OpenSSL socket wrappers).  
  All crypto operations must occur **explicitly** at the application layer.

- **Do not commit secrets** (certs, private keys, salts, `.env` values).  
  The `.gitignore` file is configured to exclude these files.

- **Use standard libraries** for cryptographic operations.  
  You are not required to implement AES, RSA, or DH math yourself.

## 📁 Generated Files

After running the application, the following files are created:

- **Certificates:** `certs/*.crt`, `certs/*.key` (gitignored)
- **Transcripts:** `transcripts/*.txt`, `transcripts/*.export.txt` (gitignored)
- **Receipts:** `transcripts/*_receipt_*.json` (gitignored)

All generated files are automatically excluded from git via `.gitignore`.

## 🧾 Deliverables

When submitting on Google Classroom (GCR):

1. **ZIP of GitHub repository** (with all commits)
2. **MySQL schema dump** and sample records
3. **Updated README.md** (this file)
4. **Report:** `RollNumber-FullName-Report-A02.docx`
5. **Test Report:** `RollNumber-FullName-TestReport-A02.docx`

### Exporting MySQL Schema Dump

To export the database schema and sample records for submission:

**Step 1: Ensure MySQL container is running**
```bash
docker ps
```
You should see `securechat-db` container running.

**Step 2: Export schema and data**
```bash
docker exec securechat-db mysqldump -u user -p12345678 securechat > schema_dump.sql
```

**Step 3: Verify the dump file**
```bash
dir schema_dump.sql
```

**Expected Output:**
- File `schema_dump.sql` should be created
- Contains `CREATE TABLE` statements
- Contains `INSERT` statements for sample users (if any exist)

**Alternative: Export schema only (no data)**
```bash
docker exec securechat-db mysqldump -u user -p12345678 --no-data securechat > schema_only.sql
```

**Alternative: Export data only (no schema)**
```bash
docker exec securechat-db mysqldump -u user -p12345678 --no-create-info securechat > data_only.sql
```

**Note:** The `schema_dump.sql` file should be included in your submission ZIP.

## 📚 Additional Resources

- **Certificate Inspection:**
  ```bash
  openssl x509 -in certs/ca.crt -text -noout
  openssl x509 -in certs/server.crt -text -noout
  openssl x509 -in certs/client.crt -text -noout
  ```

- **Database Management:**
  - Access Adminer at `http://localhost:8081`
  - View `users` table to see registered users
  - Check `pwd_hash` is 64 characters (SHA-256 hex)

- **Transcript Files:**
  - Format: `seqno|timestamp|ciphertext|signature|peer-cert-fingerprint`
  - Each line represents one message
  - Export files (`.export.txt`) are used for verification

## 🔗 GitHub Repository

[Add your GitHub repository link here]

---

**Note:** This implementation demonstrates CIANR (Confidentiality, Integrity, Authenticity, Non-Repudiation) through application-layer cryptographic protocols without using TLS/SSL.
