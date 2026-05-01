import os, sys, json, hmac, base64, hashlib, getpass, datetime
from pathlib import Path

from Crypto.PublicKey import RSA, ECC
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# ===========================================================================
# SECTION 1: CONFIGURATION
# ===========================================================================

#Sets global variables for paths to specific files
BASE_DIR          = Path(__file__).parent
DATA_DIR          = BASE_DIR / "data"
KEYS_DIR          = DATA_DIR / "keys"
FILES_DIR         = DATA_DIR / "encrypted_files"
USERS_FILE        = DATA_DIR / "users.json"
AUDIT_FILE        = DATA_DIR / "audit_log.json"
AUDIT_HMAC_FILE   = DATA_DIR / "audit_hmac.key"

# System master key — used to encrypt AES keys for auditors on justified request.
MASTER_PRIV_FILE  = KEYS_DIR / "_system_master_private.pem"
MASTER_PUB_FILE   = KEYS_DIR / "_system_master_public.pem"

#Values used in crypto methods
AES_KEY_SIZE      = 16
RSA_KEY_BITS      = 2048
PBKDF2_ITERATIONS = 310_000
PBKDF2_SALT_LEN   = 16
DSA_PASSPHRASE    = b"wm9pc_dsa_internal"

#Aux variables
ROLE_RESEARCHER   = "researcher"
ROLE_CLINICIAN    = "clinician"
ROLE_AUDITOR      = "auditor"
MAX_ATTEMPTS      = 3


def _utcnow():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def _sep(c="─", w=58):
    print(c * w)

def _hdr(t): _sep("═"); print(f"  {t}"); _sep("═")


# ===========================================================================
# SECTION 2: SIMULATION HELPERS
# ===========================================================================

#Functions that simulate security elements that aren't accurately implemented, for the purpose of demonstration of the technologies a secure system would use

def _sim_tls_send(description, payload_description):
    """[SIMULATION] TLS 1.3 — in production data travels over HTTPS."""
    print(f"\n  [TLS SIMULATION] Would transmit over TLS 1.3:")
    print(f"    Operation : {description}")
    print(f"    Payload   : {payload_description}")
    print(f"    Note      : In production sent to file server over HTTPS.")


def _sim_tls_receive(description):
    """[SIMULATION] TLS 1.3 — in production data is received over HTTPS."""
    print(f"\n  [TLS SIMULATION] Would receive over TLS 1.3:")
    print(f"    Operation : {description}")
    print(f"    Note      : In production delivered over HTTPS.")


def _sim_access_approval(username, file_id, reason):
    """[SIMULATION] Auditor access approval — in production requires data controller review."""
    print(f"\n  [ACCESS APPROVAL SIMULATION]")
    print(f"    Requestor : {username}")
    print(f"    File ID   : {file_id}")
    print(f"    Reason    : {reason}")
    print(f"    Status    : AUTO-APPROVED (simulation)")
    print(f"    Note      : In production a data controller would review")
    print(f"                and approve this request before access is granted.")


def _sim_hsm_operation(operation):
    """[SIMULATION] HSM — in production private key operations run inside hardware."""
    print(f"  [HSM SIMULATION] {operation} (simulated via PEM file)")


def _sim_session_token(username, role): #username and role are not accessed here as it is just a sim but would be needed if it was properly implemented
    """[SIMULATION] JWT — in production a signed token with expiry would be issued."""
    token = base64.b64encode(get_random_bytes(24)).decode()
    print(f"\n  [SESSION SIMULATION] Token issued: {token[:32]}... (truncated)")
    print(f"    Note: In production this would be a signed JWT with expiry.")


def _sim_audit_replication(entry_id):
    """[SIMULATION] Audit replication — in production entries replicate to a separate server."""
    print(f"  [AUDIT] Entry #{entry_id} logged.", end="\r")


# ===========================================================================
# SECTION 3: SYSTEM INITIALISATION
# ===========================================================================

# Create the test accounts/files and generate keys for them


def initialise_system():
    """Create directories, generate master key, seed test accounts."""
    for d in [DATA_DIR, KEYS_DIR, FILES_DIR]:
        d.mkdir(parents=True, exist_ok=True)

    # 256-bit HMAC key for audit log integrity
    if not AUDIT_HMAC_FILE.exists():
        AUDIT_HMAC_FILE.write_bytes(get_random_bytes(32))
        os.chmod(AUDIT_HMAC_FILE, 0o600)

    # System master RSA key pair — used to re-wrap AES keys for auditors
    if not MASTER_PRIV_FILE.exists():
        _generate_master_keypair()

    if not USERS_FILE.exists():
        _seed_test_accounts()


def _generate_master_keypair():
    """Generate the system master RSA-2048 key pair for auditor access-on-request."""
    key         = RSA.generate(RSA_KEY_BITS)
    priv_pem    = key.export_key(format="PEM").decode()
    pub_pem     = key.publickey().export_key(format="PEM").decode()
    MASTER_PRIV_FILE.write_text(priv_pem)
    MASTER_PUB_FILE.write_text(pub_pem)
    os.chmod(MASTER_PRIV_FILE, 0o600)
    print("[INIT] System master key pair generated.")


def _seed_test_accounts():
    accounts = [
        {"username": "researcher1", "password": "Researcher2026", "role": ROLE_RESEARCHER},
        {"username": "clinician1",  "password": "Clinician2026",  "role": ROLE_CLINICIAN},
        {"username": "auditor1",    "password": "Auditor2026",    "role": ROLE_AUDITOR},
    ]
    users = {}
    print("\n[INIT] Creating test accounts...")
    for acc in accounts: #For each account, hash their password and create their RSA keys
        pw_hash, salt = _hash_password(acc["password"])
        _, pub_pem = _generate_rsa_keypair(acc["username"])
        if acc["role"] != ROLE_AUDITOR: #Auditors need ECDSA keys for verifyign signatures
            _generate_ecdsa_keypair(acc["username"])
        users[acc["username"]] = {
            "password_hash":  pw_hash,
            "password_salt":  salt,
            "role":           acc["role"],
            "rsa_public_key": pub_pem,
            "created":        _utcnow(),
        }
        print(f"  {acc['username']}  {acc['password']}  [{acc['role']}]")
    USERS_FILE.write_text(json.dumps(users, indent=2))
    os.chmod(USERS_FILE, 0o600)

    print("\n[INIT] Populating test data...")
    _seed_test_files()
    print("[INIT] Done.\n")


def _seed_test_files():
    """
    Pre-populate the system with test files.
    Files are signed (ECDSA P-256)
    """
    r1_content_1 = (
        "Trial: EP-2025-441 | Phase: 1 | Cohort: A (n=24)\n"
        "Mean alpha wave frequency: 9.2 Hz (SD 0.8)\n"
        "Mean beta wave frequency:  18.4 Hz (SD 1.2)\n"
        "No significant adverse events recorded."
    ).encode()
    sig1 = base64.b64encode(sign_data(r1_content_1.decode(), "researcher1")).decode()
    store_encrypted_file(
        filename      = "EEG Study — Cohort A",
        content       = r1_content_1,
        uploader      = "researcher1",
        uploader_role = ROLE_RESEARCHER,
        allowed_users = ["researcher1"],
        signature     = sig1,
    )

    r1_content_2 = (
        "Trial: EP-2025-441 | Phase: 1 | Cohort: A (n=24)\n"
        "Fasting glucose:    mean 5.1 mmol/L (range 4.2-6.8) — all within normal range\n"
        "HbA1c:              mean 38 mmol/mol (range 31-47)\n"
        "Cholesterol:        mean 4.8 mmol/L — no hyperlipidaemia detected\n"
        "Status: Ready for phase 2 progression review."
    ).encode()
    sig2 = base64.b64encode(sign_data(r1_content_2.decode(), "researcher1")).decode()
    store_encrypted_file(
        filename      = "Blood Panel Results — Cohort A",
        content       = r1_content_2,
        uploader      = "researcher1",
        uploader_role = ROLE_RESEARCHER,
        allowed_users = ["researcher1"],
        signature     = sig2,
    )

    users = _load_users()
    clinician_users = [u for u, d in users.items() if d["role"] == ROLE_CLINICIAN]

    c1_content_1 = (
            "Screening date: 2026-03-14 | Site: WMG Medical Centre\n"
            "Patients screened: 12 | Eligible: 10 | Excluded: 2 (hypertension)\n"
            "Resting heart rate: mean 68 bpm (range 54-82)\n"
            "Blood pressure:     mean 118/76 mmHg\n"
            "ECG: no arrhythmia detected in any eligible patient.\n"
            "Next review: 2026-04-28"
        ).encode()
    sig3 = base64.b64encode(sign_data(c1_content_1.decode(), "clinician1")).decode()
    store_encrypted_file(
        filename      = "Patient Cohort B — Cardiology Screening",
        content       = c1_content_1,
        uploader      = "clinician1",
        uploader_role = ROLE_CLINICIAN,
        allowed_users = clinician_users,
        signature     = sig3,
    )

    c1_content_2 = (
            "Trial: EP-2025-441 | Week: 12 of 24\n"
            "Active arm (n=10): all doses administered on schedule\n"
            "Placebo arm (n=10): all doses administered on schedule\n"
            "Adverse events: 1 mild nausea (active arm, self-resolving)\n"
            "Protocol deviations: none\n"
            "Next administration: 2026-04-29"
        ).encode()
    sig4 = base64.b64encode(sign_data(c1_content_2.decode(), "clinician1")).decode()
    store_encrypted_file(
        filename      = "Medication Administration Log — Week 12",
        content       = c1_content_2,
        uploader      = "clinician1",
        uploader_role = ROLE_CLINICIAN,
        allowed_users = clinician_users,
        signature     = sig4,
    )

    print("  Seeded 2 signed researcher file(s) and 2 clinician file(s).")


# ===========================================================================
# SECTION 4: PASSWORD HASHING — PBKDF2-HMAC-SHA256
# ===========================================================================

def _hash_password(password):
    salt = get_random_bytes(PBKDF2_SALT_LEN) #(16)
    dk   = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS, 32)
    return dk.hex(), salt.hex()


def _verify_password(password, stored_hash, stored_salt):
    salt = bytes.fromhex(stored_salt)
    dk   = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS, 32)
    return hmac.compare_digest(dk.hex(), stored_hash)


# ===========================================================================
# SECTION 5: USER STORE
# ===========================================================================

def create_account(username, password, role):
    users = _load_users()
    if username in users:
        raise ValueError(f"Username '{username}' already exists.")
    if role not in [ROLE_RESEARCHER, ROLE_CLINICIAN, ROLE_AUDITOR]:
        raise ValueError(f"Invalid role: {role}")

    pw_hash, salt = _hash_password(password)
    _, pub_pem    = _generate_rsa_keypair(username)
    if role in [ROLE_RESEARCHER, ROLE_CLINICIAN]:
        _generate_ecdsa_keypair(username)

    users[username] = {
        "password_hash":  pw_hash,
        "password_salt":  salt,
        "role":           role,
        "rsa_public_key": pub_pem,
        "created":        _utcnow(),
    }
    _save_users(users)
    if role == ROLE_CLINICIAN:
        _rewrap_clinician_files_for_new_user(username)
    log_action("SYSTEM", "system", "ACCOUNT_CREATED", f"username={username} role={role}")
    print(f"\n  [OK] Account '{username}' created with role [{role}].")

def _load_users():
    return json.loads(USERS_FILE.read_text()) if USERS_FILE.exists() else {}

def _save_users(users):
    USERS_FILE.write_text(json.dumps(users, indent=2))
    os.chmod(USERS_FILE, 0o600)

def authenticate(username, password):
    users = _load_users()
    if username not in users:
        return None
    u = users[username]
    return u if _verify_password(password, u["password_hash"], u["password_salt"]) else None


# ===========================================================================
# SECTION 6: RSA KEY MANAGEMENT
# ===========================================================================

#Standard RSA key generation and encryption/decryption

def _generate_rsa_keypair(username):
    key         = RSA.generate(RSA_KEY_BITS)
    private_pem = key.export_key(format="PEM").decode()
    public_pem  = key.publickey().export_key(format="PEM").decode()
    priv_path   = KEYS_DIR / f"{username}_rsa_private.pem"
    priv_path.write_text(private_pem)
    os.chmod(priv_path, 0o600)
    return private_pem, public_pem

def _load_rsa_private(username):
    return RSA.import_key((KEYS_DIR / f"{username}_rsa_private.pem").read_text())

def _load_rsa_public(username):
    return RSA.import_key(_load_users()[username]["rsa_public_key"])

def rsa_encrypt_key(aes_key, recipient_username):
    """Wrap an AES key under a user's RSA-2048 public key (OAEP)."""
    cipher = PKCS1_OAEP.new(_load_rsa_public(recipient_username))
    return cipher.encrypt(aes_key)

def rsa_decrypt_key(wrapped, username):
    """Unwrap an AES key using a user's RSA-2048 private key (OAEP)."""
    cipher = PKCS1_OAEP.new(_load_rsa_private(username))
    return cipher.decrypt(wrapped)

def _master_wrap_key(aes_key):
    """Wrap an AES key under the system master public key."""
    cipher = PKCS1_OAEP.new(RSA.import_key(MASTER_PUB_FILE.read_text()))
    return cipher.encrypt(aes_key)

def _master_unwrap_key(wrapped):
    """
    Decrypt an AES key using the system master private key.
    [SIMULATION] — In production this runs inside an HSM after verifying an approved request.
    """
    _sim_hsm_operation("Master key unwrap")
    cipher = PKCS1_OAEP.new(RSA.import_key(MASTER_PRIV_FILE.read_text()))
    return cipher.decrypt(wrapped)


# ===========================================================================
# SECTION 7: AES-128-CBC ENCRYPTION
# ===========================================================================

def aes_cbc_encrypt(plaintext, key):
    iv     = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct     = cipher.encrypt(pad(plaintext, AES.block_size))
    return iv, ct

def aes_cbc_decrypt(iv, ciphertext, key):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size)


# ===========================================================================
# SECTION 8: HMAC-SHA256 INTEGRITY
# ===========================================================================

def compute_hmac(key, data):
    return hmac.new(key, data, hashlib.sha256).hexdigest()

def verify_hmac_value(key, data, expected):
    return hmac.compare_digest(compute_hmac(key, data), expected)


# ===========================================================================
# SECTION 9: ENCRYPTED FILE STORE
# ===========================================================================

def store_encrypted_file(filename, content, uploader, uploader_role, allowed_users, signature=None):
    """
    Encrypt and store a file.
    - allowed_users: specific usernames who may decrypt (not roles).
      Researchers: uploader only. Clinicians: all clinicians. Auditors: use request workflow.
    - AES key is also wrapped under the master key for auditor access-on-request.
    - signature: optional base64-encoded ECDSA signature over the plaintext.
    """
    aes_key        = get_random_bytes(AES_KEY_SIZE)
    iv, ciphertext = aes_cbc_encrypt(content, aes_key)
    mac            = compute_hmac(aes_key, iv + ciphertext)

    wrapped_keys = {}
    for uname in allowed_users:
        wrapped_keys[uname] = base64.b64encode(rsa_encrypt_key(aes_key, uname)).decode()

    master_wrapped = base64.b64encode(_master_wrap_key(aes_key)).decode()

    file_id = hashlib.sha256(
        f"{filename}{uploader}{_utcnow()}".encode()
    ).hexdigest()[:16]

    record = {
        "file_id":        file_id,
        "filename":       filename,
        "uploader":       uploader,
        "uploader_role":  uploader_role,
        "timestamp":      _utcnow(),
        "allowed_users":  allowed_users,
        "iv":             base64.b64encode(iv).decode(),
        "ciphertext":     base64.b64encode(ciphertext).decode(),
        "hmac":           mac,
        "wrapped_keys":   wrapped_keys,
        "master_wrapped": master_wrapped,
        "auditor_access_log": [],
        "signature":      signature,
        "signed_by":      uploader if signature else None,
    }

    _sim_tls_send(
        f"Upload encrypted file '{filename}'",
        f"IV + ciphertext ({len(ciphertext)} bytes) + HMAC + "
        f"{len(wrapped_keys)} wrapped key(s) + master key"
    )
    (FILES_DIR / f"{file_id}.json").write_text(json.dumps(record, indent=2))
    return file_id


def request_auditor_access(file_id, auditor_username, reason):
    """
    Grant an auditor access to a specific file after written justification.
    Implements UK GDPR Article 5(1)(c) — auditors have no standing content access.
    The master key re-wraps the AES key for the auditor; access is logged with reason.
    """
    path = FILES_DIR / f"{file_id}.json"
    if not path.exists():
        raise FileNotFoundError(f"File '{file_id}' not found.")

    record = json.loads(path.read_text())

    if auditor_username in record["wrapped_keys"]:
        print(f"\n  [INFO] {auditor_username} already has access to this file.")
        return

    _sim_access_approval(auditor_username, file_id, reason)

    aes_key = _master_unwrap_key(base64.b64decode(record["master_wrapped"]))
    record["wrapped_keys"][auditor_username] = base64.b64encode(
        rsa_encrypt_key(aes_key, auditor_username)
    ).decode()

    record["auditor_access_log"].append({
        "auditor":     auditor_username,
        "granted":     _utcnow(),
        "reason":      reason,
        "approved_by": "AUTO-APPROVED (simulation — production requires data controller)"
    })

    path.write_text(json.dumps(record, indent=2))
    print(f"\n  [ACCESS GRANTED] {auditor_username} may now decrypt file '{file_id}'.")
    print(f"  This access grant has been recorded in the file's audit log.")


def retrieve_decrypted_file(file_id, username, role):
    """
    Retrieve and decrypt a stored file.
    HMAC is verified before decryption (Encrypt-then-MAC).
    Auditors must have previously called request_auditor_access().
    """
    _sim_tls_receive(f"Download encrypted record for file_id='{file_id}'")

    path = FILES_DIR / f"{file_id}.json"
    if not path.exists():
        raise FileNotFoundError(f"File '{file_id}' not found.")

    record = json.loads(path.read_text())

    if username not in record["wrapped_keys"]:
        if role == ROLE_AUDITOR:
            raise PermissionError(
                "Access denied. As an auditor you must first submit an access "
                "request with justification (option 4a) before decrypting this file."
            )
        raise PermissionError("Access denied: no key for this file.")

    aes_key = rsa_decrypt_key(base64.b64decode(record["wrapped_keys"][username]), username)
    iv = base64.b64decode(record["iv"])
    ciphertext = base64.b64decode(record["ciphertext"])

    if not verify_hmac_value(aes_key, iv + ciphertext, record["hmac"]):
        raise ValueError("INTEGRITY FAILURE: HMAC verification failed.")

    return aes_cbc_decrypt(iv, ciphertext, aes_key), record.get("signature"), record.get("signed_by")


def list_files_for_role(role, username=None):
    """
    Return file metadata accessible to a given role/user.
    Researchers: own uploads only. Clinicians: all files with a wrapped key.
    Auditors: all file metadata (content requires justified request).
    """
    result = []
    for p in FILES_DIR.glob("*.json"):
        r = json.loads(p.read_text())
        wk = r.get("wrapped_keys", {})
        if role == ROLE_AUDITOR:
            visible = True
            has_access = username in wk if username else False
        else:
            visible = username in wk if username else False
            has_access = visible
        if visible:
            result.append({
                "file_id":        r["file_id"],
                "filename":       r["filename"],
                "uploader":       r["uploader"],
                "time":           r["timestamp"],
                "access_granted": has_access,
            })
    return result

def _rewrap_clinician_files_for_new_user(new_username):
    """Use the master key to give a new clinician access to all existing clinician files."""
    for p in FILES_DIR.glob("*.json"):
        record = json.loads(p.read_text())
        if record.get("uploader_role") != ROLE_CLINICIAN:
            continue
        if new_username in record["wrapped_keys"]:
            continue
        aes_key = _master_unwrap_key(base64.b64decode(record["master_wrapped"]))
        record["wrapped_keys"][new_username] = base64.b64encode(
            rsa_encrypt_key(aes_key, new_username)
        ).decode()
        p.write_text(json.dumps(record, indent=2))


# ===========================================================================
# SECTION 10: ECDSA DIGITAL SIGNATURES (FIPS 186-5 approved)
# ===========================================================================

def _generate_ecdsa_keypair(username):
    """Generate an ECDSA P-256 key pair (FIPS 186-5 approved, ~128-bit security)."""
    key     = ECC.generate(curve="P-256")
    priv_pem = key.export_key(
        format="PEM",
        passphrase=DSA_PASSPHRASE.decode(),
        protection="PBKDF2WithHMAC-SHA1AndAES128-CBC"
    )
    pub_pem  = key.public_key().export_key(format="PEM")
    priv_path = KEYS_DIR / f"{username}_ecdsa_private.pem"
    priv_path.write_bytes(priv_pem.encode() if isinstance(priv_pem, str) else priv_pem)
    os.chmod(priv_path, 0o600)
    pub_bytes = pub_pem.encode() if isinstance(pub_pem, str) else pub_pem
    (KEYS_DIR / f"{username}_ecdsa_public.pem").write_bytes(pub_bytes)


def sign_data(text, username):
    """Sign text using ECDSA P-256 + SHA-256 (FIPS 186-5 approved)."""
    with open(KEYS_DIR / f"{username}_ecdsa_private.pem", "rb") as f:
        private_key = ECC.import_key(f.read(), passphrase=DSA_PASSPHRASE.decode())
    h = SHA256.new(text.encode("utf-8"))
    signer = DSS.new(private_key, "fips-186-3")
    return signer.sign(h)


def verify_signature(text, signature, signer_username):
    """Verify an ECDSA P-256 signature (FIPS 186-5 approved)."""
    with open(KEYS_DIR / f"{signer_username}_ecdsa_public.pem", "rb") as f:
        public_key = ECC.import_key(f.read())
    h = SHA256.new(text.encode("utf-8"))
    verifier = DSS.new(public_key, "fips-186-3")
    try:
        verifier.verify(h, signature)
        return True
    except ValueError:
        return False


# ===========================================================================
# SECTION 11: AUDIT LOG
# ===========================================================================

def _get_audit_key():
    return AUDIT_HMAC_FILE.read_bytes()

def _load_audit():
    return json.loads(AUDIT_FILE.read_text()) if AUDIT_FILE.exists() else []

def _save_audit(log):
    AUDIT_FILE.write_text(json.dumps(log, indent=2))


def log_action(username, role, action, details="", gdpr_note=""):
    """Append a tamper-evident HMAC-protected entry to the audit log."""
    key   = _get_audit_key()
    log   = _load_audit()
    entry = {
        "id":        len(log),
        "timestamp": _utcnow(),
        "username":  username,
        "role":      role,
        "action":    action,
        "details":   details,
    }
    if gdpr_note:
        entry["gdpr_note"] = gdpr_note
    canonical = json.dumps({k: v for k, v in entry.items()}, sort_keys=True).encode()
    entry["mac"] = hmac.new(key, canonical, hashlib.sha256).hexdigest()
    log.append(entry)
    _save_audit(log)
    _sim_audit_replication(entry["id"])


def verify_audit_integrity():
    key, tampered = _get_audit_key(), []
    for entry in _load_audit():
        stored = entry.get("mac", "")
        canonical = json.dumps(
            {k: v for k, v in entry.items() if k != "mac"}, sort_keys=True
        ).encode()
        expected  = hmac.new(key, canonical, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(stored, expected):
            tampered.append(entry["id"])
    return len(tampered) == 0, tampered


# ===========================================================================
# SECTION 12: ROLE MENUS
# ===========================================================================

def researcher_menu(username, role):
    while True:
        _hdr("RESEARCHER PORTAL")
        print("1. Encrypt, sign and upload research data")
        print("2. Decrypt and view research data")
        print("3. Logout")
        _sep()
        choice = input("  Select: ").strip()

        if choice == "1":
            label   = input("\n  Data label: ").strip()
            content = input("  Enter data: ").strip().encode()

            # Sign plaintext before encryption — binds signature to original content
            # at creation time, preventing ciphertext substitution attacks.
            sig     = sign_data(content.decode(), username)
            sig_b64 = base64.b64encode(sig).decode()
            print(f"\n  [SIGNING] Content signed with ECDSA P-256 at upload time.")

            fid = store_encrypted_file(label, content, username, role,
                                       [username], signature=sig_b64)
            log_action(username, role, "UPLOAD_AND_SIGN_RESEARCH",
                       f"label='{label}' id={fid} signed=True")
            print(f"  [OK] File ID: {fid}")

        elif choice == "2":
            files = list_files_for_role(role, username)
            if not files:
                print("\n  [INFO] No files available."); continue
            print()
            for f in files:
                print(f"  [{f['file_id']}]  {f['filename']}  by {f['uploader']}")
            fid = input("\n  File ID: ").strip()
            try:
                data, sig_b64, signed_by = retrieve_decrypted_file(fid, username, role)
                log_action(username, role, "DECRYPT_RESEARCH", f"id={fid}")
                print(f"\n  [DATA]\n  {data.decode()}")
                if sig_b64 and signed_by:
                    valid = verify_signature(data.decode(), base64.b64decode(sig_b64), signed_by)
                    status = "VALID ✓" if valid else "INVALID ✗"
                    print(f"\n  [SIGNATURE] Signed by '{signed_by}' at upload — {status}")
            except Exception as e:
                print(f"\n  [ERROR] {e}")

        elif choice == "3":
            log_action(username, role, "LOGOUT"); break


def clinician_menu(username, role):
    while True:
        _hdr("CLINICIAN PORTAL")
        print("1. Upload encrypted patient dataset")
        print("2. Retrieve and decrypt patient dataset")
        print("3. Logout")
        _sep()
        choice = input("  Select: ").strip()

        if choice == "1":
            label   = input("\n  Dataset label: ").strip()
            content = input("  Enter patient data: ").strip().encode()
            users = _load_users()
            clinician_users = [u for u, d in users.items() if d["role"] == ROLE_CLINICIAN]
            sig     = sign_data(content.decode(), username)
            sig_b64 = base64.b64encode(sig).decode()
            print(f"\n  [SIGNING] Content signed with ECDSA P-256 at upload time.")
            fid     = store_encrypted_file(label, content, username, role,
                                           clinician_users, signature=sig_b64)
            log_action(username, role, "UPLOAD_PATIENT", f"label='{label}' id={fid}")
            print(f"\n  [OK] File ID: {fid}")

        elif choice == "2":
            files = list_files_for_role(role, username)
            if not files:
                print("\n  [INFO] No files available."); continue
            print()
            for f in files:
                print(f"  [{f['file_id']}]  {f['filename']}  by {f['uploader']}")
            fid = input("\n  File ID: ").strip()
            try:
                data, sig_b64, signed_by = retrieve_decrypted_file(fid, username, role)
                log_action(username, role, "RETRIEVE_PATIENT", f"id={fid}")
                print(f"\n  [DATA]\n  {data.decode()}")
                if sig_b64 and signed_by:
                    valid = verify_signature(data.decode(), base64.b64decode(sig_b64), signed_by)
                    status = "VALID ✓" if valid else "INVALID ✗"
                    print(f"\n  [SIGNATURE] Signed by '{signed_by}' at upload — {status}")
            except Exception as e:
                print(f"\n  [ERROR] {e}")

        elif choice == "3":
            log_action(username, role, "LOGOUT"); break


def auditor_menu(username, role):
    """
    Auditor menu — implements UK GDPR Article 5(1)(c) data minimisation.
    Standing access: audit log, file metadata, signature verification.
    Requires justification: actual file content (options 4a/4b).
    """
    while True:
        _hdr("AUDITOR PORTAL")
        print("1.  View audit log")
        print("2.  Verify audit log integrity (HMAC)")
        print("3.  View file metadata (all files — no content)")
        print("4a. Request access to specific file content (requires justification)")
        print("4b. Decrypt file (only if access previously granted)")
        print("5.  Verify a document signature (ECDSA P-256)")
        print("6.  Logout")
        _sep()
        choice = input("  Select: ").strip()

        if choice == "1":
            log = _load_audit()
            log_action(username, role, "VIEW_AUDIT_LOG", f"entries={len(log)}")
            if not log:
                print("\n  [INFO] Log empty."); continue
            print()
            print("  # TIMESTAMP USER ROLE ACTION DETAILS")
            _sep()
            for e in log:
                gdpr = f" [GDPR: {e['gdpr_note']}]" if e.get("gdpr_note") else ""
                print(f"  {e['id']} {e['timestamp']} {e['username']} "
                      f"{e['role']} {e['action']} {e.get('details','')}{gdpr}")

        elif choice == "2":
            ok, bad = verify_audit_integrity()
            log_action(username, role, "VERIFY_AUDIT_INTEGRITY",
                       f"result={'PASS' if ok else 'FAIL'}")
            print(f"\n  [{'OK' if ok else 'ALERT'}] "
                  f"{'All entries intact ✓' if ok else f'Tampered IDs: {bad}'}")

        elif choice == "3":
            files = list_files_for_role(role, username)
            if not files:
                print("\n  [INFO] No files found."); continue
            log_action(username, role, "VIEW_FILE_METADATA",
                       f"files_visible={len(files)}")
            print()
            print("  FILE ID  FILENAME  UPLOADER  UPLOADED  CONTENT ACCESS")
            _sep()
            for f in files:
                access_status = "Granted" if f.get("access_granted") else "Not requested"
                print(f"{f['file_id']}  {f['filename']}  "
                      f"{f['uploader']}  {f['time']}  {access_status}")
            print()
            print("  Note: Viewing metadata does not constitute content access.")
            print("        Use option 4a to request justified content access.")

        elif choice == "4a":
            print("\nUK GDPR Article 5(1)(c) requires that auditor access to\nfile content is justified, proportionate, and documented.")
            print()
            fid    = input("File ID to request access to: ").strip()
            reason = input("Documented reason for access (e.g. regulatory review,\n"
                           "incident investigation): ").strip()
            if not reason:
                print("\n  [ERROR] A reason is required to request file access.")
                continue
            try:
                request_auditor_access(fid, username, reason)
                log_action(
                    username, role, "AUDITOR_ACCESS_REQUEST",
                    f"id={fid} reason='{reason}'",
                    gdpr_note="Article 5(1)(c) justified access request"
                )
            except Exception as e:
                print(f"\n  [ERROR] {e}")

        elif choice == "4b":
            files = list_files_for_role(role, username)
            if not files:
                print("\n  [INFO] No files found."); continue
            print()
            for f in files:
                status = "ACCESS GRANTED" if f.get("access_granted") else "no access"
                print(f"  [{f['file_id']}]  {f['filename']}  [{status}]")
            fid = input("\n  File ID to decrypt: ").strip()
            try:
                data, sig_b64, signed_by = retrieve_decrypted_file(fid, username, role)
                log_action(
                    username, role, "AUDITOR_CONTENT_ACCESS",
                    f"id={fid}",
                    gdpr_note="Article 5(1)(c) justified content decryption"
                )
                print(f"\n  [DATA]\n  {data.decode()}")
            except Exception as e:
                print(f"\n  [ERROR] {e}")

        elif choice == "5":
            fid = input("\n  File ID to verify: ").strip()
            rec_path = FILES_DIR / f"{fid}.json"
            if not rec_path.exists():
                print(f"\n  [ERROR] File '{fid}' not found.")
                continue
            record    = json.loads(rec_path.read_text())
            sig_b64   = record.get("signature")
            signed_by = record.get("signed_by")
            if not sig_b64 or not signed_by:
                print("\n  [INFO] This file has no signature.")
                continue
            try:
                # Decrypt to recover plaintext — requires prior access request (option 4a)
                plaintext, _, _ = retrieve_decrypted_file(fid, username, role)
                valid = verify_signature(plaintext.decode(), base64.b64decode(sig_b64), signed_by)
            except PermissionError:
                print("\n  [ERROR] You must request access to this file (option 4a) before verifying its signature.")
                continue
            except Exception as e:
                print(f"\n  [ERROR] {e}")
                continue
            log_action(username, role, "VERIFY_SIG", f"id={fid} signer={signed_by} valid={valid}")
            print(f"\n  [SIGNATURE] Signed by '{signed_by}' at upload — {'VALID ✓' if valid else 'INVALID ✗'}")

        elif choice == "6":
            log_action(username, role, "LOGOUT"); break


# ===========================================================================
# SECTION 13: MAIN ENTRY POINT
# ===========================================================================

def main():
    print()
    _sep("═", 60)
    print("  Secure Clinical Research Collaboration Platform")
    _sep("═", 60)
    print()

    initialise_system() #Create the test accounts and seed files

    print("  [R] Register a new account")
    print("  [L] Login")
    choice = input("  Select: ").strip().upper()
    if choice == "R":
        username = input("  New username: ").strip()
        password = getpass.getpass("  New password: ")
        role     = input("  Role (researcher/clinician/auditor): ").strip().lower()
        try:
            create_account(username, password, role)
        except ValueError as e:
            print(f"\n  [ERROR] {e}")

    for attempt in range(1, MAX_ATTEMPTS + 1):
        print(f"\n  Login attempt {attempt}/{MAX_ATTEMPTS}")
        username = input("  Username: ").strip()
        password = getpass.getpass("  Password: ") #Silences the echo during password entry

        user = authenticate(username, password)
        if user is None:
            remaining = MAX_ATTEMPTS - attempt
            print(f"  [ERROR] Invalid credentials."
                  f"{f' {remaining} attempt(s) left.' if remaining else ''}")
            if not remaining:
                print("  [LOCKED] Exiting.")
            continue

        role = user["role"]
        print(f"\n  [LOGIN] Welcome, {username}! Role: {role.upper()}")
        _sim_session_token(username, role)
        log_action(username, role, "LOGIN", "Authenticated")

        if   role == ROLE_RESEARCHER: 
            researcher_menu(username, role)
        elif role == ROLE_CLINICIAN:  
            clinician_menu(username, role)
        elif role == ROLE_AUDITOR:    
            auditor_menu(username, role)

        print("\n  [SESSION] Goodbye.\n")
        return

    sys.exit(1)


if __name__ == "__main__":
    main()