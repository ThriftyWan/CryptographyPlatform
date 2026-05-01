# Secure Clinical Research Collaboration Platform

A command-line application implementing a cryptographically secure platform for sharing sensitive patient and research data across institutions. Built with Python and `pycryptodome`.

#KEYS ARE EXPOSED PURPOSEFULLY FOR DEMO PURPOSES, IN REALITY THEY WOULD BE STORED IN A HSM  

---

## Installation

**Requires Python 3.8+**

```bash
pip install pycryptodome
python secure_platform.py
```

On first run the system automatically creates the `data/` directory, generates all key material, and seeds three test accounts with four pre-populated files.

---

## Test Accounts

| Username | Password | Role |
|---|---|---|
| `researcher1` | `Researcher2026` | Researcher |
| `clinician1` | `Clinician2026` | Clinician |
| `auditor1` | `Auditor2026` | Auditor |

---

## Roles and Permissions

### Researcher
- Encrypt, sign, and upload research data
- Decrypt and view own files only — other researchers' files are not visible or accessible
- ECDSA P-256 signature is applied automatically at upload and verified automatically on decryption

### Clinician
- Upload and retrieve encrypted patient datasets
- Access is shared across all registered clinicians — any clinician can access any clinician file, reflecting the shared care model
- ECDSA P-256 signature applied and verified in the same way as researchers

### Auditor
- View the full audit log and verify its HMAC integrity
- View file metadata (filenames, uploaders, timestamps) for all files without content access
- Request justified access to specific file content — a written reason is required
- Decrypt a file only after an access request has been approved
- Verify a file's ECDSA signature using just the file ID

---

## Auditor Workflow

The auditor has no standing access to file content. To read a file:

1. **Option 3** — view file metadata to find the file ID
2. **Option 4a** — submit a written justification for access to that file ID
3. **Option 4b** — decrypt the file (only available after step 2)
4. **Option 5** — verify the file's signature using the file ID (also requires step 2)

This enforces UK GDPR Article 5(1)(c) data minimisation at the cryptographic level — access is granted by re-wrapping the file's AES key under the auditor's RSA public key using the system master key.

---

## Cryptographic Design

| Component | Algorithm | Standard |
|---|---|---|
| Password hashing | PBKDF2-HMAC-SHA256, 310,000 iterations | NIST SP 800-132 |
| Symmetric encryption | AES-128-CBC with PKCS7 padding | FIPS 197 |
| Integrity | HMAC-SHA256 (Encrypt-then-MAC) | RFC 2104 |
| Key wrapping | RSA-2048 OAEP per user | NIST SP 800-131A |
| Digital signatures | ECDSA P-256 + SHA-256 | FIPS 186-5 |
| Audit log integrity | HMAC-SHA256 per entry | RFC 2104 |

### Key design decisions

**Per-username key wrapping** — the AES key for each file is encrypted separately under each authorised user's RSA public key. Researcher files are wrapped for the uploader only; clinician files are wrapped for all registered clinicians. This means an unauthorised user cannot recover the AES key even with direct filesystem access.

**Encrypt-then-MAC** — the HMAC is computed over the ciphertext after encryption and verified before decryption. This prevents the Padding Oracle Attack: a tampered ciphertext is rejected before the AES layer is reached.

**Master key** — a system RSA key pair wraps a copy of each file's AES key at upload time. This copy is used to re-wrap keys for auditors on justified request, and to re-wrap keys for newly registered clinicians so they immediately have access to existing files.

**Signatures at upload** — ECDSA signatures are computed over the plaintext before encryption. Verification happens automatically on every decryption, confirming both the content and the identity of the signer.

---

## Account Registration

At the pre-login prompt select `R` to register a new account:

```
[R] Register a new account
[L] Login
```

Provide a username, password, and role (`researcher`, `clinician`, or `auditor`). Registering a new clinician automatically grants them access to all existing clinician files via the master key re-wrap mechanism.

---

## Directory Structure

```
data/
├── keys/
│   ├── <username>_rsa_private.pem      # RSA-2048 private key (0o600)
│   ├── <username>_rsa_public.pem       # RSA-2048 public key (stored in users.json)
│   ├── <username>_ecdsa_private.pem    # ECDSA P-256 private key (researchers and clinicians only)
│   ├── <username>_ecdsa_public.pem     # ECDSA P-256 public key
│   ├── _system_master_private.pem      # Master RSA private key (0o600)
│   └── _system_master_public.pem       # Master RSA public key
├── encrypted_files/
│   └── <file_id>.json                  # Encrypted file record
├── users.json                          # User credentials and public keys (0o600)
├── audit_log.json                      # HMAC-protected audit log
└── audit_hmac.key                      # Audit log HMAC key (0o600)
```

Each encrypted file record contains the base64-encoded IV, ciphertext, HMAC, wrapped AES keys per user, master-wrapped AES key, and the ECDSA signature if present.

---

## Simulated Components

The following production infrastructure components are simulated locally and marked with `[SIMULATION]` in the output:

- **TLS 1.3** — all file uploads and downloads would travel over HTTPS in production
- **PKI / Certificate Authority** — public keys are stored as raw PEM files; a CA would bind them to verified identities via X.509 certificates
- **Hardware Security Module** — the master private key and all private key operations would run inside tamper-resistant hardware; the key bytes would never be exposed in memory
- **Data controller approval** — auditor access requests are auto-approved; in production a data controller would review each request before the master key operation runs
- **Session tokens / JWT** — sessions have no expiry; a signed JWT with a short validity window would be used in production
- **Remote audit log replication** — the audit log and HMAC key are co-located; in production the log would replicate in real time to a physically separate server

---

## Security Notes

- Plaintext is never written to disk
- Private keys are stored with `0o600` file permissions
- Login enforces a three-attempt lockout; error messages are uniform regardless of whether the username or password is wrong, preventing username enumeration
- The audit log HMAC key is stored separately from the log; tampering with any log entry is detected by the auditor's integrity check (option 2)
- To reset the system entirely, delete the `data/` directory and re-run
