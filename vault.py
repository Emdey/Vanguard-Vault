# ============================================================
# VANGUARD VAULT — PAID-READY COMMERCIAL EDITION
# ============================================================

# --- Core ---
import logging
import streamlit as st
import os
import io
import base64
import hashlib
import secrets
import string
from datetime import datetime, timedelta
import tempfile
import math
import bcrypt
import re
import zlib
from reedsolo import RSCodec
import random
import io
import numpy as np
from argon2 import PasswordHasher




# --- Data & Utilities ---
import pandas as pd
import hmac

# --- Image / Video ---
from PIL import Image
try:
    import cv2
    CV2_AVAILABLE = True
except ModuleNotFoundError:
    CV2_AVAILABLE = False

import numpy as np
import stepic  # For image steganography

# --- Cryptography ---
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding, dh
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend


# --- Database ---
from supabase import create_client, Client

# --- Custom Styling / Utilities ---
from style import apply_custom_theme, show_status


apply_custom_theme()
show_status()



# ============================================================
# PAGE CONFIG & BRANDING
# ============================================================

st.set_page_config(
    page_title="Vanguard Vault",
    page_icon="🛡️",
    layout="wide"
)


# ==============================
# Supabase Initialization
# ==============================
S_URL = st.secrets.get("SUPABASE_URL")
S_KEY = st.secrets.get("SUPABASE_KEY")

if not S_URL or not S_KEY:
    st.error("❌ Configuration Missing: Check your Streamlit Secrets.")
    st.stop()

from supabase import create_client, Client

try:
    conn: Client = create_client(S_URL, S_KEY)

    # Hard connection test
    conn.table("users").select("*").limit(1).execute()

    st.sidebar.success("📡 Database Linked")

except Exception as e:
    st.error(f"❌ Supabase Connection Failed: {e}")
    st.info("Ensure the Supabase project is ACTIVE (not paused).")
    st.stop()


# ============================================================
# GLOBAL CONFIG
# ============================================================

MAX_AES_FILE_MB = 100
MAX_VIDEO_MB = 50

ADMIN_USERNAME = "ADELL_ADMIN"
FREE_LIMIT = 5
SESSION_TIMEOUT_MIN = 30

BANK_INFO = "BANK: Opay | ACCT: 9112587745 | NAME: ADELL TECH"
WHATSAPP_NUMBER = "2347059194126"
FLUTTERWAVE_LINK = "#"  # Replace when live

# ============================================================
# SESSION ISOLATION & TIMEOUT
# ============================================================

def init_session():
    if "aes_ciphertext" not in st.session_state:
        st.session_state.aes_ciphertext = ""
    if "auth" not in st.session_state:
        st.session_state.auth = {"user": None, "login_time": None}
    if "crypto" not in st.session_state:
        st.session_state.crypto = {}
    if "hash_output" not in st.session_state:
        st.session_state.hash_output = ""


def enforce_session_timeout():
    if st.session_state.auth["login_time"]:
        if datetime.utcnow() - st.session_state.auth["login_time"] > timedelta(minutes=SESSION_TIMEOUT_MIN):
            secure_logout()

def secure_logout():
    for k in list(st.session_state.keys()):
        del st.session_state[k]
    st.success("🔒 Logged out due to inactivity. Please log in again to continue.")
    st.rerun()

    

init_session()
enforce_session_timeout()

# ============================================================
# 🔐 VAULT UNLOCK — MASTER KEY MANAGEMENT (PRODUCTION)
# ============================================================

# ------------------ SESSION STATE ---------------------------
if "vault" not in st.session_state:
    st.session_state.vault = {
        "unlocked": False,
        "master_key": None,
        "salt": None,
        "unlocked_at": None
    }

# ------------------ KEY DERIVATION --------------------------
def derive_master_key(password: str, salt: bytes) -> bytes:
    kdf = Scrypt(
        salt=salt,
        length=32,        # 256-bit master key
        n=2**15,
        r=8,
        p=1,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# ------------------ VAULT UNLOCK UI -------------------------
def vault_unlock_ui():
    st.subheader("🔐 Unlock Vault")

    password = st.text_input(
        "Vault Passphrase",
        type="password",
        key="vault_passphrase"
    )

    if st.button("Unlock Vault", key="vault_unlock_btn"):
        if len(password) < 12:
            st.error("Passphrase must be at least 12 characters.")
            st.stop()

        if not st.session_state.vault["salt"]:
            st.session_state.vault["salt"] = os.urandom(16)

        try:
            master_key = derive_master_key(
                password,
                st.session_state.vault["salt"]
            )

            st.session_state.vault["master_key"] = master_key
            st.session_state.vault["unlocked"] = True
            st.session_state.vault["unlocked_at"] = datetime.utcnow()

            st.success("Vault unlocked.")
            st.rerun()

        except Exception:
            st.error("Failed to unlock vault.")

# ------------------ HARD VAULT GUARD -------------------------
def require_vault():
    if not st.session_state.vault["unlocked"]:
        vault_unlock_ui()
        st.stop()

# ------------------ MANUAL LOCK -----------------------------
def lock_vault():
    st.session_state.vault = {
        "unlocked": False,
        "master_key": None,
        "salt": None,
        "unlocked_at": None
    }

if st.sidebar.button("🔒 Lock Vault"):
    lock_vault()
    st.warning("Vault locked. Keys wiped from memory.")
    st.rerun()


# ============================================================
# PASSWORD HASHING & VALIDATION (SECURITY HARDENING)
# ============================================================

def hash_password(password: str) -> str:
    """Hash password using bcrypt."""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(password: str, stored_hash: str) -> bool:
    """
    Verifies password.
    Supports legacy SHA-256 hashes and bcrypt hashes.
    """
    if stored_hash.startswith("$2"):
        return bcrypt.checkpw(password.encode(), stored_hash.encode())
    else:
        return hashlib.sha256(password.encode()).hexdigest() == stored_hash


def validate_password_strength(password: str) -> tuple[bool, str]:
    if len(password) < 12:
        return False, "Password must be at least 12 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must include an uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must include a lowercase letter."
    if not re.search(r"[0-9]", password):
        return False, "Password must include a number."
    if not re.search(r"[!@#$%^&*()_+=\-{}[\]:;\"'<>,.?/\\|]", password):
        return False, "Password must include a special character."
    return True, ""


# ============================================================
# RATE LIMITING (LOGIN ABUSE CONTROL)
# ============================================================

def rate_limit(identifier, action, max_attempts=5, window_min=10):
    now = datetime.utcnow()
    window = now - timedelta(minutes=window_min)

    res = conn.table("rate_limits") \
        .select("*") \
        .eq("identifier", identifier) \
        .eq("action", action) \
        .gte("last_attempt", window.isoformat()) \
        .execute()

    if res.data:
        r = res.data[0]
        if r["count"] >= max_attempts:
            return False
        conn.table("rate_limits").update({
            "count": r["count"] + 1,
            "last_attempt": now.isoformat()
        }).eq("id", r["id"]).execute()
    else:
        conn.table("rate_limits").insert({
            "identifier": identifier,
            "action": action,
            "count": 1,
            "last_attempt": now.isoformat()
        }).execute()
    return True

# ============================================================
# AUDIT LOGGING
# ============================================================

def audit(user, action):
    conn.table("logs").insert({
        "username": user,
        "action": action
    }).execute()

# ============================================================
# USAGE, BILLING & PAYWALL
# ============================================================

def get_usage(user: str) -> int:
    """Fetch the number of operations a user has performed."""
    try:
        res = conn.table("users").select("op_count").eq("username", user).execute()
        if res.data and len(res.data) > 0:
            return int(res.data[0].get("op_count", 0))
        return 0
    except Exception as e:
        st.error(f"Error fetching usage for {user}: {e}")
        return 0


def increment_usage(user_name: str, action: str) -> None:
    if user_name == ADMIN_USERNAME:
        return
    try:
        curr = get_usage(user_name)
        # Update Database
        conn.table("users").update({"op_count": curr + 1}).eq("username", user_name).execute()
        # Log the action
        audit(user_name, action)
        # Force a rerun so the Sidebar Metric updates immediately
        st.rerun() 
    except Exception as e:
        st.error(f"Error: {e}")

def check_usage_limit(user: str) -> bool:
    """
    Returns True if the user is allowed to perform another operation.
    If limit is reached, displays a paywall message.
    """
    if user == ADMIN_USERNAME:
        return True

    usage = get_usage(user)

    if usage >= FREE_LIMIT:
        # Safely render paywall
        st.markdown(
    f"""
    <div style="
        padding: 16px;
        background: #120406;
        border-radius: 8px;
        border: 1px solid #ff4d4f;
        box-shadow: 0 0 15px rgba(255, 77, 79, 0.35);
        color: #ffb3b3;
        font-family: monospace;
    ">
        🔒 <b>CREDIT LIMIT REACHED</b><br>
        Pay <b>₦200</b> to unlock 5 more operations.<br>
        <code style="color:#00f2ff;">{BANK_INFO}</code><br><br>
        <a href="https://wa.me/{WHATSAPP_NUMBER}?text=Proof:{user}"
           style="color:#00f2ff;font-weight:bold;"
           target="_blank">
            📩 Send Proof on WhatsApp
        </a>
    </div>
    """,
    unsafe_allow_html=True
)

        return False

    return True


# ============================================================
# VANGUARD VAULT — AUTH MODULE (SUPABASE-PRODUCTION READY)
# ============================================================


# ------------------ SESSION INIT ----------------------------
if "auth" not in st.session_state:
    st.session_state.auth = {"user": None, "login_time": None}
if "vault" not in st.session_state:
    st.session_state.vault = {
        "aes_key": None,
        "rsa_public": None,
        "rsa_private": None,
        "hmac_key": None,
        "dh_shared": None
    }


# ------------------ HARD AUTH GUARD -------------------------
def require_auth():
    if not st.session_state.auth.get("user"):
        st.stop()

# ------------------ PASSWORD SECURITY ----------------------
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(password: str, stored_hash: str) -> bool:
    return bcrypt.checkpw(password.encode(), stored_hash.encode())

def validate_password_strength(password: str):
    if len(password) < 12:
        return False, "Password must be at least 12 characters."
    if not any(c.isupper() for c in password):
        return False, "Password must include an uppercase letter."
    if not any(c.islower() for c in password):
        return False, "Password must include a lowercase letter."
    if not any(c.isdigit() for c in password):
        return False, "Password must include a number."
    if not any(c in string.punctuation for c in password):
        return False, "Password must include a special character."
    return True, ""

# ------------------ RECOVERY -------------------------------
def generate_recovery_code(length=12):
    return "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(length))

def hash_recovery_code(rc: str) -> str:
    return hashlib.sha256(rc.encode()).hexdigest()

# ------------------ RATE LIMIT -----------------------------
def rate_limit(identifier, action, max_attempts=5, window_min=15):
    from supabase import create_client
    now = datetime.utcnow()
    window = now - timedelta(minutes=window_min)
    try:
        res = conn.table("rate_limits") \
            .select("*") \
            .eq("identifier", identifier) \
            .eq("action", action) \
            .gte("last_attempt", window.isoformat()) \
            .execute()
        if res.data:
            r = res.data[0]
            if r["count"] >= max_attempts:
                return False
            conn.table("rate_limits").update({
                "count": r["count"] + 1,
                "last_attempt": now.isoformat()
            }).eq("id", r["id"]).execute()
        else:
            conn.table("rate_limits").insert({
                "identifier": identifier,
                "action": action,
                "count": 1,
                "last_attempt": now.isoformat()
            }).execute()
        return True
    except Exception as e:
        st.error(f"Rate limit check failed: {e}")
        return False

# ------------------ AUDIT LOGGING --------------------------
def audit(user, action):
    try:
        conn.table("logs").insert({
            "username": user,
            "action": action
        }).execute()
    except Exception as e:
        st.warning(f"Audit log failed: {e}")

# ============================================================
# AUTH UI
# ============================================================

if not st.session_state.auth["user"]:
    st.title("🛡️ VANGUARD VAULT")
    tab_login, tab_register = st.tabs(["Login", "Register"])

    # ---------------- LOGIN ----------------
    with tab_login:
        login_user = st.text_input("Username", key="login_user")
        login_pass = st.text_input("Passkey", type="password", key="login_pass")

        if st.button("Access Vault", key="login_btn"):
            if not rate_limit(login_user, "LOGIN"):
                st.error("Too many login attempts. Try later.")
                st.stop()

            try:
                res = conn.table("users").select("*").eq("username", login_user).execute()
                if not res.data:
                    st.error("Invalid credentials.")
                    st.stop()

                user_row = res.data[0]
                if verify_password(login_pass, user_row["password"]):
                    st.session_state.auth["user"] = login_user
                    st.session_state.auth["login_time"] = datetime.utcnow()
                    audit(login_user, "LOGIN")
                    st.success(f"Logged in as {login_user}")
                    st.rerun()
                else:
                    st.error("Invalid credentials.")
            except Exception as e:
                st.error(f"Login failed: {e}")

    # ---------------- REGISTER ----------------
    with tab_register:
        reg_user = st.text_input("New Username", key="reg_user")
        reg_pass = st.text_input("New Passkey", type="password", key="reg_pass")
        agree = st.checkbox("I accept the Terms of Service", key="reg_tos")

        if st.button("Create Identity", key="reg_btn") and agree:
            if not rate_limit(reg_user, "REGISTER", 3, 30):
                st.error("Too many registration attempts. Wait 30 minutes.")
                st.stop()

            valid, msg = validate_password_strength(reg_pass)
            if not valid:
                st.error(msg)
                st.stop()

            # Check for duplicates
            try:
                existing = conn.table("users").select("username").eq("username", reg_user).execute()
                if existing.data:
                    st.error("Username already exists.")
                    st.stop()

                rc = generate_recovery_code()
                conn.table("users").insert({
                    "username": reg_user,
                    "password": hash_password(reg_pass),
                    "recovery_hash": hash_recovery_code(rc),
                    "op_count": 0,
                    "payment_count": 0
                }).execute()

                st.success("Account created.")
                st.warning("SAVE THIS RECOVERY CODE")
                st.code(rc)
                audit(reg_user, "REGISTER")
            except Exception as e:
                st.error(f"Registration failed: {e}")

    # ---------------- RECOVERY ----------------
    with st.expander("🔑 Forgot Passkey?"):
        rec_user = st.text_input("Username", key="rec_user")
        rec_code = st.text_input("Recovery Code", key="rec_code")
        rec_pass = st.text_input("New Passkey", type="password", key="rec_pass")

        if st.button("Reset Passkey", key="rec_btn"):
            if not rate_limit(rec_user, "RECOVERY", 3, 30):
                st.error("Too many recovery attempts. Try later.")
                st.stop()

            try:
                res = conn.table("users").select("*").eq("username", rec_user).execute()
                if not res.data:
                    st.error("Invalid recovery details.")
                    st.stop()

                user_row = res.data[0]
                if hash_recovery_code(rec_code) != user_row["recovery_hash"]:
                    st.error("Invalid recovery code.")
                    st.stop()

                valid, msg = validate_password_strength(rec_pass)
                if not valid:
                    st.error(msg)
                    st.stop()

                # Update password & new recovery hash
                new_rc = generate_recovery_code()
                conn.table("users").update({
                    "password": hash_password(rec_pass),
                    "recovery_hash": hash_recovery_code(new_rc)
                }).eq("username", rec_user).execute()

                st.success("Passkey reset successful.")
                st.warning("SAVE THIS NEW RECOVERY CODE")
                st.code(new_rc)
                audit(rec_user, "RECOVERY_RESET")
            except Exception as e:
                st.error(f"Recovery failed: {e}")

    st.stop()  # Absolute auth barrier

# ============================================================
# AUTHENTICATED AREA
# ============================================================
require_auth()

st.success(f"Welcome, {st.session_state.auth['user']}")

if st.button("Logout"):
    audit(st.session_state.auth["user"], "LOGOUT")
    st.session_state.auth = {"user": None, "login_time": None}
    st.rerun()

# ============================================================
# SMART DYNAMIC SIDEBAR — VANGUARD VAULT (FINAL)
# ============================================================

# --- GUARANTEE VAULT EXISTS (ONCE) ---
if "vault" not in st.session_state:
    st.session_state.vault = {
        "aes_key": None,
        "rsa_private": None,
        "rsa_public": None,
        "dh_shared_key": None,
        "hmac_key": None
    }

user = st.session_state.auth["user"]
vault = st.session_state.vault  # SAFE REFERENCE

with st.sidebar:
    st.title("VANGUARD")
    st.caption(f"Operator: {user}")

    # --- CRITICAL KEY WARNINGS ---
    critical_keys = ["aes_key", "rsa_private"]
    missing = [k for k in critical_keys if not vault[k]]

    if missing:
        st.warning(
            "⚠️ Missing critical keys:\n"
            + ", ".join(missing)
            + "\nGenerate them before encryption."
        )

    st.markdown("### 🔐 Crypto Vault Status")

    status_map = {
        "aes_key": ("AES Key", "Symmetric encryption"),
        "rsa_private": ("RSA Private Key", "Hybrid decryption"),
        "rsa_public": ("RSA Public Key", "Hybrid encryption"),
        "dh_shared_key": ("DH Shared Key", "Ephemeral session key"),
        "hmac_key": ("HMAC Key", "Integrity verification")
    }

    keys_exist = False

    for key, (label, desc) in status_map.items():
        present = vault[key] is not None
        keys_exist |= present
        color = "#00ffcc" if present else "#ff4d4f"
        state = "Loaded" if present else "Missing"

        st.markdown(
            f"**{label}:** <span style='color:{color}'>{state}</span>",
            unsafe_allow_html=True
        )
        st.caption(desc)

    # --- CLEAR VAULT (ONLY WHEN NEEDED) ---
    if keys_exist:
        st.markdown("---")
        confirm = st.checkbox("⚠️ Confirm: clear all crypto keys", key="confirm_clear_keys")

        if st.button("🧹 Clear All Crypto Keys"):
            if confirm:
                for k in vault:
                    vault[k] = None
                st.success("Cryptographic vault cleared.")
                st.rerun()
            else:
                st.warning("Confirmation required.")

    # --- USAGE MONITOR ---
    st.markdown("---")
    st.subheader("📊 Usage Monitor")

    current_usage = get_usage(user)
    st.metric("Credits Used", f"{current_usage} / {FREE_LIMIT}")
    st.progress(min(current_usage / FREE_LIMIT, 1.0))

    if current_usage >= FREE_LIMIT:
        st.warning("🔒 Usage limit reached.")

    # --- LOGOUT ---
    st.markdown("---")
    if st.button("🚪 Logout"):
        secure_logout()


# ============================================================
# MODULE SELECTION

menu = [
    "AES Symmetric",
    "RSA Hybrid",
    "Diffie-Hellman",
    "Hashing and Integrity",
    "Steganography",
    "📡 Support",
    "ℹ️ About",
    "🆘 Help & Guide"  
]

if user == ADMIN_USERNAME:
    menu.insert(0, "👑 ADMIN")

mode = st.selectbox("Module", menu)

# ============================================================
# AES SYMMETRIC MODULE
# ============================================================
if mode == "AES Symmetric":
    st.header("🛡️ AES-256 Symmetric Locker")
    tab_keygen, tab_text, tab_file = st.tabs(["🔑 KEYGEN", "📝 Text Locker", "🎬 File/Video Vault"])

    # ---------------- 1. AES KEY GENERATION ----------------
    require_vault()

    # Initialize AES key state
    if "aes_key" not in st.session_state:
        st.session_state.aes_key = None
    if "aes_key_size" not in st.session_state:
        st.session_state.aes_key_size = 256  # default

    with tab_keygen:
        st.subheader("🔐 AES Symmetric Key Generator")

        # Key size selector
        st.session_state.aes_key_size = st.selectbox(
            "Select AES Key Size (bits)",
            options=[128, 192, 256],
            index=[128, 192, 256].index(st.session_state.aes_key_size)
        )

        # Function to generate AES key
        def generate_aes_key():
            key_size_bytes = st.session_state.aes_key_size // 8
            return base64.urlsafe_b64encode(os.urandom(key_size_bytes)).decode()

        # Generate new AES key
        if st.button("Generate New AES Key"):
            st.session_state.vault["aes_key"] = generate_aes_key()
            st.session_state.aes_key = st.session_state.vault["aes_key"]
            st.success(f"✅ AES-{st.session_state.aes_key_size} key generated!")

        # Display current AES key if exists
        if st.session_state.vault.get("aes_key"):
            st.markdown("**Current AES Key:**")
            st.code(st.session_state.vault["aes_key"])

            # Clear AES key button
            if st.button("Clear AES Key"):
                st.session_state.vault["aes_key"] = None
                st.session_state.aes_key = None
                st.success("AES key cleared.")

        # Manual AES key input
    manual_key_input = st.text_input("Or Paste Your Own AES Key (Base64)", key="manual_aes_key")
    if st.button("Set Manual AES Key") and manual_key_input:
        try:
            decoded_key = base64.urlsafe_b64decode(manual_key_input.encode())
            if len(decoded_key) not in [16, 24, 32]:
                st.error("Invalid AES key length. Must be 16, 24, or 32 bytes.")
            else:
                st.session_state.vault["aes_key"] = manual_key_input
                st.session_state.aes_key = manual_key_input
                st.success("✅ Manual AES Key Set!")
        except Exception as e:
            st.error(f"Invalid Base64 key format: {e}")

    # ---------------- 2. KEY SELECTION ----------------
    st.markdown("---")
    key_mode = st.radio("Key Source:", ["Use Master Password", "Use Manual AES Key"])
    fernet = None

    if key_mode == "Use Master Password":
        m_pass = st.text_input("Master Password", type="password")
        if m_pass:
            static_salt = hashlib.sha256(user.encode()).digest()[:16]
            kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=static_salt, iterations=200_000)
            derived = base64.urlsafe_b64encode(kdf.derive(m_pass.encode()))
            fernet = Fernet(derived)
    else:
        manual_key = st.text_input("Paste Manual AES Key", type="password", help="Enter your Base64 key here.")
        if manual_key:
            try:
                fernet = Fernet(manual_key.encode())
            except Exception as e:
                st.error(f"Invalid Key Format: {e}")
                fernet = None

    # ---------------- 3. TEXT LOCKER ----------------
    with tab_text:
        if fernet:
            col1, col2 = st.columns(2)
            with col1:
                plaintext = st.text_area("Plaintext to Encrypt")
                if st.button("🔒 Encrypt Text") and plaintext and check_usage_limit(user):
                    st.session_state.aes_ciphertext = fernet.encrypt(plaintext.encode()).decode()
                    increment_usage(user, "AES_TEXT_ENC")

            with col2:
                ciphertext = st.text_area("Ciphertext to Decrypt")
                if st.button("🔓 Decrypt Text") and ciphertext:
                    try:
                        decrypted = fernet.decrypt(ciphertext.encode()).decode()
                        st.success("Decryption Successful!")
                        st.write(decrypted)
                    except:
                        st.error("Decryption Failed: Invalid Key or Corrupt Data")
        else:
            st.info("Provide a password or AES key above to use the text locker.")

    # ---------------- 4. FILE/VIDEO VAULT ----------------
    with tab_file:
        if fernet:
            file_upload = st.file_uploader("Upload File/Video")
            if file_upload:
                if file_upload.size > MAX_AES_FILE_MB * 1024 * 1024:
                    st.error(f"File too large. Maximum allowed is {MAX_AES_FILE_MB} MB.")
                    st.stop()

                if st.button("📦 Execute File Lock") and check_usage_limit(user):
                    enc_data = fernet.encrypt(file_upload.read())
                    st.download_button(
                        f"📥 Download {file_upload.name}.vanguard",
                        enc_data,
                        f"{file_upload.name}.vanguard"
                    )
                    increment_usage(user, "AES_FILE_ENC")

            vault_upload = st.file_uploader("Upload .vanguard Vault to Unlock", type=["vanguard"])
            if vault_upload and st.button("🔓 Decrypt Vault") and check_usage_limit(user):
                try:
                    dec_data = fernet.decrypt(vault_upload.read())
                    st.success("Vault Unlocked!")
                    st.download_button("📥 Download Original File", dec_data, "restored_file")
                    increment_usage(user, "AES_FILE_DEC")
                except:
                    st.error("Decryption Failed: Invalid Key or Corrupt Data")
        else:
            st.info("Provide a password or AES key above to use the file vault.")




# ============================================================
# RSA–AES HYBRID MODULE (FINALIZED)
# ============================================================

elif mode == "RSA Hybrid":
    require_vault()

    st.header("🔐 RSA–AES Hybrid Encryption System")

    tab_keys, tab_encrypt, tab_decrypt = st.tabs(
        ["🔑 Key Management", "🔒 Encrypt File", "🔓 Decrypt File"]
    )

    # --------------------------------------------------------
    # 1. KEY MANAGEMENT
    # --------------------------------------------------------
    with tab_keys:
        st.subheader("RSA Keypair")

        # Display status
        has_private = st.session_state.vault["rsa_private"] is not None
        has_public = st.session_state.vault["rsa_public"] is not None

        st.markdown(
            f"""
            **Private Key:** {"Loaded" if has_private else "Missing"}  
            **Public Key:** {"Loaded" if has_public else "Missing"}
            """
        )

        # Generate RSA keys (ONLY if missing)
        if not has_private and not has_public:
            if st.button("Generate RSA Keypair (4096-bit)") and check_usage_limit(user):
                if not rate_limit(user, "RSA_KEYGEN", max_attempts=3, window_min=15):
                    st.error("RSA generation rate-limited. Try later.")
                    st.stop()

                try:
                    private_key = rsa.generate_private_key(
                        public_exponent=65537,
                        key_size=4096
                    )

                    public_key = private_key.public_key()

                    st.session_state.vault["rsa_private"] = private_key
                    st.session_state.vault["rsa_public"] = public_key

                    st.success("✅ RSA-4096 keypair generated.")
                    increment_usage(user, "RSA_KEYGEN_4096")
                    st.rerun()

                except Exception as e:
                    st.error(f"RSA generation failed: {e}")

        else:
            st.info("RSA keypair already loaded. Clear vault to regenerate.")

    # --------------------------------------------------------
    # 2. HYBRID ENCRYPTION
    # --------------------------------------------------------
    with tab_encrypt:
        st.subheader("Encrypt File (AES + RSA)")

        if not st.session_state.vault["rsa_public"]:
            st.warning("RSA public key required.")
            st.stop()

        file = st.file_uploader("Select file to encrypt")

        if file:
            if file.size > MAX_AES_FILE_MB * 1024 * 1024:
                st.error(f"File exceeds {MAX_AES_FILE_MB} MB limit.")
                st.stop()

            if st.button("🔒 Encrypt File") and check_usage_limit(user):
                try:
                    # Generate AES session key
                    session_key = Fernet.generate_key()
                    fernet = Fernet(session_key)

                    encrypted_payload = fernet.encrypt(file.read())

                    # Encrypt AES key with RSA
                    rsa_pub = st.session_state.vault["rsa_public"]
                    encrypted_key = rsa_pub.encrypt(
                        session_key,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )

                    st.success("✅ File encrypted successfully.")

                    st.markdown("**Encrypted Session Key (Send with file)**")
                    st.code(base64.b64encode(encrypted_key).decode())

                    st.download_button(
                        "📥 Download Encrypted File",
                        encrypted_payload,
                        file.name + ".vault"
                    )

                    increment_usage(user, "RSA_HYBRID_ENC")

                except Exception as e:
                    st.error(f"Encryption failed: {e}")

    # --------------------------------------------------------
    # 3. HYBRID DECRYPTION
    # --------------------------------------------------------
    with tab_decrypt:
        st.subheader("Decrypt Hybrid Vault")

        if not st.session_state.vault["rsa_private"]:
            st.warning("RSA private key required.")
            st.stop()

        enc_key_input = st.text_area("Encrypted Session Key (Base64)")
        vault_file = st.file_uploader("Upload .vault file", type=["vault"])

        if enc_key_input and vault_file:
            if st.button("🔓 Decrypt File") and check_usage_limit(user):
                try:
                    rsa_priv = st.session_state.vault["rsa_private"]

                    session_key = rsa_priv.decrypt(
                        base64.b64decode(enc_key_input),
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )

                    fernet = Fernet(session_key)
                    decrypted_data = fernet.decrypt(vault_file.read())

                    st.success("🔓 Decryption successful.")

                    st.download_button(
                        "📥 Download Restored File",
                        decrypted_data,
                        "restored_file"
                    )

                    increment_usage(user, "RSA_HYBRID_DEC")

                except Exception as e:
                    st.error("Decryption failed. Check key and file integrity.")


# ============================================================
# HASHING & INTEGRITY MODULE (GENERATION + VERIFICATION)
# ============================================================
elif mode == "Hashing & Integrity":
    st.header("🧾 Hashing & Integrity Verification")

    tab_text, tab_file = st.tabs(["📝 Text", "📂 File"])

    # ---------------- OPERATION MODE ----------------
    operation = st.radio(
        "Operation Type",
        ["Generate Digest", "Verify Digest"],
        horizontal=True
    )

    integrity_type = st.radio(
        "Integrity Method",
        ["Standard Hash", "HMAC"],
        horizontal=True
    )

    # ---------------- ALGORITHM SELECTION ----------------
    if integrity_type == "Standard Hash":
        algo = st.selectbox("Algorithm", ["SHA-256", "SHA-512", "BLAKE2b"])
    else:
        algo = st.selectbox("Algorithm", ["HMAC-SHA256", "HMAC-SHA512"])

        if not st.session_state.vault.get("hmac_key"):
            st.warning("⚠️ HMAC requires a secret key stored in the vault.")
            st.stop()

    # ---------------- BACKEND ----------------
    def compute_hash(data: bytes) -> str:
        if algo == "SHA-256":
            return hashlib.sha256(data).hexdigest()
        if algo == "SHA-512":
            return hashlib.sha512(data).hexdigest()
        if algo == "BLAKE2b":
            return hashlib.blake2b(data).hexdigest()

    def compute_hmac(data: bytes) -> str:
        key = st.session_state.vault["hmac_key"]
        if algo == "HMAC-SHA256":
            return hmac.new(key, data, hashlib.sha256).hexdigest()
        if algo == "HMAC-SHA512":
            return hmac.new(key, data, hashlib.sha512).hexdigest()

    # ---------------- TEXT MODE ----------------
    with tab_text:
        text_input = st.text_area("Input Text")

        expected = None
        if operation == "Verify Digest":
            expected = st.text_input("Expected Digest (hex)")

        if st.button("Execute") and text_input and check_usage_limit(user):
            data = text_input.encode()

            try:
                actual = (
                    compute_hash(data)
                    if integrity_type == "Standard Hash"
                    else compute_hmac(data)
                )

                if operation == "Generate Digest":
                    st.success("Digest generated")
                    st.code(actual)
                    increment_usage(user, f"{integrity_type}_GEN_{algo}")

                else:
                    if hmac.compare_digest(actual, expected.strip()):
                        st.success("✅ Digest VERIFIED — Integrity OK")
                    else:
                        st.error("❌ Digest MISMATCH — Data altered or wrong key")

                    increment_usage(user, f"{integrity_type}_VERIFY_{algo}")

            except Exception as e:
                st.error(f"Operation failed: {e}")

    # ---------------- FILE MODE ----------------
    with tab_file:
        file = st.file_uploader("Upload File")

        expected = None
        if operation == "Verify Digest":
            expected = st.text_input("Expected Digest (hex)", key="file_digest")

        if file and st.button("Execute File Operation") and check_usage_limit(user):
            try:
                data = file.read()

                actual = (
                    compute_hash(data)
                    if integrity_type == "Standard Hash"
                    else compute_hmac(data)
                )

                if operation == "Generate Digest":
                    st.success("Digest generated")
                    st.code(actual)
                    increment_usage(user, f"{integrity_type}_FILE_GEN_{algo}")

                else:
                    if hmac.compare_digest(actual, expected.strip()):
                        st.success("✅ File VERIFIED — Integrity OK")
                    else:
                        st.error("❌ File FAILED verification")

                    increment_usage(user, f"{integrity_type}_FILE_VERIFY_{algo}")

            except Exception as e:
                st.error(f"Operation failed: {e}")


# ============================================================
# DIFFIE–HELLMAN KEY EXCHANGE MODULE (WITH FILE/VIDEO SUPPORT)
# ============================================================

elif mode == "Diffie-Hellman":
    require_vault()

    st.header("🔁 Diffie–Hellman Secure Key Exchange")

    tab_exchange, tab_text, tab_file = st.tabs(
        ["🔑 Key Exchange", "📝 Text Locker", "🎬 File/Video Vault"]
    )

    # --------------------------------------------------------
    # 1. KEY EXCHANGE
    # --------------------------------------------------------
    with tab_exchange:
        st.subheader("Establish Shared Secret")

        if "dh_session_key" not in st.session_state:
            st.session_state.dh_session_key = None

        if st.session_state.dh_session_key:
            st.success("✅ DH session key already established.")
            st.info("You can clear the key to re-initiate exchange.")

        if st.button("Initiate DH Exchange") and check_usage_limit(user):
            try:
                parameters = dh.generate_parameters(generator=2, key_size=2048)
                private_key = parameters.generate_private_key()
                public_key = private_key.public_key()

                peer_public_input = st.text_area(
                    "Paste Peer Public Key (PEM)",
                    help="Exchange this with the other party securely."
                )

                pub_pem = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode()
                st.markdown("**Your Public Key (Share this)**")
                st.code(pub_pem)

                if peer_public_input:
                    peer_public = serialization.load_pem_public_key(
                        peer_public_input.encode()
                    )

                    shared_secret = private_key.exchange(peer_public)
                    derived_key = HKDF(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=None,
                        info=b"vanguard-dh-session",
                    ).derive(shared_secret)

                    st.session_state.dh_session_key = base64.urlsafe_b64encode(
                        derived_key
                    ).decode()

                    st.success("🔐 Shared DH session key established.")
                    increment_usage(user, "DH_EXCHANGE")
                    st.experimental_rerun()

            except Exception as e:
                st.error(f"Key exchange failed: {e}")

        if st.button("Clear DH Session Key") and st.session_state.dh_session_key:
            st.session_state.dh_session_key = None
            st.warning("DH session key cleared.")

    # --------------------------------------------------------
    # 2. TEXT LOCKER
    # --------------------------------------------------------
    with tab_text:
        if not st.session_state.dh_session_key:
            st.info("Establish a DH session key above to use the text locker.")
        else:
            fernet = Fernet(st.session_state.dh_session_key.encode())
            col1, col2 = st.columns(2)

            with col1:
                plaintext = st.text_area("Plaintext to Encrypt")
                if st.button("🔒 Encrypt Text") and plaintext and check_usage_limit(user):
                    st.session_state.dh_ciphertext = fernet.encrypt(plaintext.encode()).decode()
                    st.code(st.session_state.dh_ciphertext)
                    increment_usage(user, "DH_TEXT_ENC")

            with col2:
                ciphertext = st.text_area("Ciphertext to Decrypt")
                if st.button("🔓 Decrypt Text") and ciphertext:
                    try:
                        decrypted = fernet.decrypt(ciphertext.encode()).decode()
                        st.success("Decryption Successful!")
                        st.write(decrypted)
                        increment_usage(user, "DH_TEXT_DEC")
                    except:
                        st.error("Decryption Failed: Invalid Key or Corrupt Data")

    # --------------------------------------------------------
    # 3. FILE/VIDEO VAULT
    # --------------------------------------------------------
    with tab_file:
        if not st.session_state.dh_session_key:
            st.info("Establish a DH session key above to use the file/video vault.")
        else:
            fernet = Fernet(st.session_state.dh_session_key.encode())

            file_upload = st.file_uploader("Upload File/Video to Encrypt")
            if file_upload:
                if file_upload.size > MAX_AES_FILE_MB * 1024 * 1024:
                    st.error(f"File too large. Maximum allowed is {MAX_AES_FILE_MB} MB.")
                elif st.button("📦 Execute File Lock") and check_usage_limit(user):
                    enc_data = fernet.encrypt(file_upload.read())
                    st.download_button(
                        f"📥 Download {file_upload.name}.vault",
                        enc_data,
                        f"{file_upload.name}.vault"
                    )
                    increment_usage(user, "DH_FILE_ENC")

            vault_upload = st.file_uploader("Upload .vault File to Decrypt", type=["vault"])
            if vault_upload and st.button("🔓 Decrypt Vault") and check_usage_limit(user):
                try:
                    dec_data = fernet.decrypt(vault_upload.read())
                    st.success("Vault Unlocked!")
                    st.download_button(
                        "📥 Download Original File",
                        dec_data,
                        "restored_file"
                    )
                    increment_usage(user, "DH_FILE_DEC")
                except:
                    st.error("Decryption Failed: Invalid Key or Corrupt Data")




# ============================================================
# STEGANOGRAPHY MODULE 
# ============================================================
# ---------------- Logging Setup ----------------
LOG_FILE = "stego_activity.log"
logging.basicConfig(filename=LOG_FILE,
                    level=logging.INFO,
                    format='%(asctime)s | %(user)s | %(action)s | %(media)s | %(message)s')

def log_stego_activity(user, action, media_type, msg_length=None, success=True):
    """Log stego actions for analytics and commercial auditing."""
    status = "SUCCESS" if success else "FAIL"
    msg_info = f"msg_len={msg_length}" if msg_length else ""
    logging.info(f"{status}", extra={
        'user': user,
        'action': action,
        'media': media_type,
        'message': msg_info
    })

# ---------------- Crypto Utilities ----------------
def derive_fernet(password, user_salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=user_salt,
        iterations=200_000
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return Fernet(key)

def encode_with_rs(data_bytes, ecc_bytes=20):
    rsc = RSCodec(ecc_bytes)
    return rsc.encode(data_bytes)

def decode_with_rs(data_bytes, ecc_bytes=20):
    rsc = RSCodec(ecc_bytes)
    return rsc.decode(data_bytes)

# ---------------- Main Stego Functions ----------------
def run_stego_hide(user):
    """Hide message in image or video."""
    user_salt = hashlib.sha256(user.encode()).digest()[:16]
    media_type = st.radio("Media Type", ["Image (PNG)", "Video (MP4/AVI)"])
    secret_msg = st.text_area("Secret Message")
    password = st.text_input("Encryption Password", type="password")

    if st.button("Encrypt & Hide") and secret_msg and password and check_usage_limit(user):
        try:
            fernet = derive_fernet(password, user_salt)
            enc_msg = fernet.encrypt(secret_msg.encode())
            enc_msg_rs = encode_with_rs(enc_msg)

            # ---------------- Image ----------------
            if media_type == "Image (PNG)":
                img_file = st.file_uploader("Upload Cover Image", type=["png"])
                if img_file:
                    img = Image.open(img_file).convert('RGB')
                    st.image(img, caption="Preview")
                    max_bytes = (img.width * img.height * 3) // 8
                    if len(enc_msg_rs) > max_bytes:
                        st.warning(f"Message too large! Max: {max_bytes} bytes")
                        trim_ratio = st.slider("Trim message (%)", 50, 100, 90)
                        trim_len = int(max_bytes * trim_ratio / 100)
                        enc_msg_rs = enc_msg_rs[:trim_len]

                    np.random.seed(int.from_bytes(hashlib.sha256(password.encode()).digest(), 'big'))
                    flat = np.array(img).flatten()
                    msg_bits = np.unpackbits(np.frombuffer(enc_msg_rs, dtype=np.uint8))
                    indices = np.random.choice(len(flat), size=len(msg_bits), replace=False)
                    flat[indices] = (flat[indices] & 0xFE) | msg_bits
                    stego_img = Image.fromarray(flat.reshape(img.size[1], img.size[0], 3))

                    buf = io.BytesIO()
                    stego_img.save(buf, format='PNG')
                    st.download_button("Download Stego Image", buf.getvalue(), "stego.png")
                    increment_usage(user, "STEGO_HIDE")
                    log_stego_activity(user, "STEGO_HIDE", "Image", msg_length=len(enc_msg_rs))

            # ---------------- Video ----------------
            elif media_type == "Video (MP4/AVI)":
                if not CV2_AVAILABLE:
                    st.error("Video functionality unavailable")
                else:
                    vid_file = st.file_uploader("Upload Video", type=["mp4", "avi"])
                    if vid_file:
                        tmp_vid = tempfile.NamedTemporaryFile(delete=False, suffix=".mp4")
                        tmp_vid.write(vid_file.read())
                        tmp_vid.flush()

                        cap = cv2.VideoCapture(tmp_vid.name)
                        fps = cap.get(cv2.CAP_PROP_FPS)
                        width, height = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH)), int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
                        total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
                        bits_per_frame = width * height * 3
                        max_bytes = (bits_per_frame * total_frames) // 8

                        if len(enc_msg_rs) > max_bytes:
                            st.warning(f"Message too large! Max: {max_bytes} bytes")
                            trim_ratio = st.slider("Trim message (%)", 50, 100, 90)
                            trim_len = int(max_bytes * trim_ratio / 100)
                            enc_msg_rs = enc_msg_rs[:trim_len]

                        msg_bits = np.unpackbits(np.frombuffer(enc_msg_rs, dtype=np.uint8))
                        bit_idx, frame_counter = 0, 0
                        frames_needed = math.ceil(len(msg_bits) / bits_per_frame)
                        progress_bar = st.progress(0)

                        out_temp = tempfile.NamedTemporaryFile(delete=False, suffix=".mp4")
                        out = cv2.VideoWriter(out_temp.name, cv2.VideoWriter_fourcc(*'mp4v'), fps, (width, height))

                        while True:
                            ret, frame = cap.read()
                            if not ret: break
                            flat_frame = frame.flatten()
                            for i in range(len(flat_frame)):
                                if bit_idx < len(msg_bits):
                                    flat_frame[i] = (flat_frame[i] & 0xFE) | msg_bits[bit_idx]
                                    bit_idx += 1
                                else:
                                    break
                            out.write(flat_frame.reshape(frame.shape))
                            frame_counter += 1
                            progress_bar.progress(min(frame_counter / frames_needed, 1.0))
                            if bit_idx >= len(msg_bits): break

                        while True:
                            ret, frame = cap.read()
                            if not ret: break
                            out.write(frame)

                        cap.release()
                        out.release()
                        progress_bar.empty()

                        st.download_button("Download Stego Video", open(out_temp.name,'rb').read(), f"stego_{vid_file.name}")
                        increment_usage(user, "VIDEO_STEGO_HIDE")
                        log_stego_activity(user, "VIDEO_STEGO_HIDE", "Video", msg_length=len(enc_msg_rs))

        except Exception as e:
            st.error(f"Stego Encoding Failed: {e}")
            log_stego_activity(user, "STEGO_HIDE", media_type, msg_length=len(secret_msg), success=False)

def run_stego_extract(user):
    """Extract message from image or video."""
    user_salt = hashlib.sha256(user.encode()).digest()[:16]
    media_type = st.radio("Media Type", ["Image (PNG)", "Video (MP4/AVI)"], key="extract_type")
    password = st.text_input("Decryption Password", type="password", key="extract_pass")

    if st.button("Extract & Decrypt") and password and check_usage_limit(user):
        try:
            fernet = derive_fernet(password, user_salt)

            # ---------------- Image ----------------
            if media_type == "Image (PNG)":
                img_file = st.file_uploader("Upload Stego Image", type=["png"])
                if img_file:
                    img = Image.open(img_file).convert('RGB')
                    flat = np.array(img).flatten()
                    np.random.seed(int.from_bytes(hashlib.sha256(password.encode()).digest(), 'big'))
                    msg_len_estimate = flat.size // 8
                    indices = np.random.choice(len(flat), size=msg_len_estimate*8, replace=False)
                    bits = np.array([flat[i] & 1 for i in indices], dtype=np.uint8)
                    data = np.packbits(bits).tobytes()
                    decrypted_msg = fernet.decrypt(decode_with_rs(data))
                    st.text_area("Extracted Message", decrypted_msg.decode())
                    increment_usage(user, "STEGO_EXTRACT")
                    log_stego_activity(user, "STEGO_EXTRACT", "Image", msg_length=len(data))

            # ---------------- Video ----------------
            elif media_type == "Video (MP4/AVI)":
                if not CV2_AVAILABLE:
                    st.error("Video functionality unavailable")
                else:
                    vid_file = st.file_uploader("Upload Stego Video", type=["mp4", "avi"])
                    if vid_file:
                        tmp_vid = tempfile.NamedTemporaryFile(delete=False, suffix=".mp4")
                        tmp_vid.write(vid_file.read())
                        tmp_vid.flush()

                        cap = cv2.VideoCapture(tmp_vid.name)
                        total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
                        bits = []
                        progress_bar = st.progress(0)

                        while True:
                            ret, frame = cap.read()
                            if not ret: break
                            bits.extend([val & 1 for val in frame.flatten()])
                            progress_bar.progress(min(cap.get(cv2.CAP_PROP_POS_FRAMES)/total_frames,1.0))

                        cap.release()
                        progress_bar.empty()

                        total_bytes = len(bits)//8
                        data = np.packbits(bits[:total_bytes*8]).tobytes()
                        decrypted_msg = fernet.decrypt(decode_with_rs(data))
                        st.text_area("Extracted Message", decrypted_msg.decode())
                        increment_usage(user, "VIDEO_STEGO_EXTRACT")
                        log_stego_activity(user, "VIDEO_STEGO_EXTRACT", "Video", msg_length=len(data))

        except Exception as e:
            st.error(f"Stego Extraction Failed: {e}")
            log_stego_activity(user, "STEGO_EXTRACT", media_type, success=False)

# ---------------- Mode Integration ----------------
if mode == "Steganography" and user:
    st.header("🕵️‍♂️ Steganography Suite")
    st.info("Hide encrypted messages within images or videos using LSB + Reed-Solomon + Fernet.")

    tab_hide, tab_reveal = st.tabs(["🔒 Hide Message", "🔓 Reveal Message"])
    with tab_hide:
        run_stego_hide(user)
    with tab_reveal:
        run_stego_extract(user)



# ============================================================
# SUPPORT MODULE — USER-SIDE TICKET HISTORY 
# ============================================================
if mode == "📡 Support":
    st.header("📡 Support & Assistance")

    st.markdown("""
Submit a support ticket if you encounter issues, billing problems, or need help using Vanguard Vault.
Your ticket history is displayed below.
""")

    # --- Ticket Submission ---
    subject = st.text_input("Subject")
    priority = st.selectbox(
        "Priority Level",
        ["LOW", "MEDIUM", "HIGH"],
        help="Use HIGH only for critical issues or payment problems."
    )
    message = st.text_area("Describe your issue")

    if st.button("Submit Ticket"):
        if not subject or not message:
            st.warning("All fields are required.")
        else:
            try:
                # Insert ticket into Supabase
                conn.table("support_tickets").insert({
                    "username": user,
                    "subject": subject,
                    "message": message,
                    "priority": priority.upper(),
                    "status": "OPEN",
                    "timestamp": datetime.utcnow().isoformat()
                }).execute()

                # Audit log
                audit(user, "SUPPORT_TICKET_CREATED")

                st.success("✅ Ticket submitted successfully. It will appear in your history below.")
                st.rerun()  # Auto-refresh to show newly created ticket

            except Exception as e:
                st.error(f"Submission failed: {e}")

    # --- User-Side Ticket History ---
    st.markdown("---")
    st.subheader("📨 My Support Tickets")

    try:
        tickets = conn.table("support_tickets") \
            .select("*") \
            .eq("username", user) \
            .order("timestamp", desc=True) \
            .execute().data

        if tickets:
            for t in tickets:
                ticket_priority = t.get("priority", "NORMAL")
                ticket_status = t.get("status", "OPEN")
                # Color coding for priority
                color = {
                    "HIGH": "#ff4d4f",
                    "MEDIUM": "#faad14",
                    "LOW": "#52c41a"
                }.get(ticket_priority.upper(), "#1890ff")

                with st.expander(f"#{t['id']} | {t['subject']} | {ticket_status} | {ticket_priority}"):
                    st.markdown(f"**Priority:** <span style='color:{color};font-weight:bold'>{ticket_priority}</span>", unsafe_allow_html=True)
                    st.markdown(f"**Status:** {ticket_status}")
                    st.markdown(f"**Submitted:** {t['timestamp']}")
                    st.markdown("---")
                    st.write(t['message'])
        else:
            st.info("No support tickets submitted yet.")

    except Exception as e:
        st.error(f"Unable to load ticket history: {e}")

    # --- Direct Contact ---
    st.markdown("---")
    st.subheader("📞 Direct Contact")
    st.markdown(
        f"""
- **WhatsApp Support:** [Chat Now](https://wa.me/{WHATSAPP_NUMBER})
- Include your **username** and **ticket subject** when contacting support.
"""
    )



# ============================================================
# ABOUT MODULE
# ============================================================
if mode == "ℹ️ About":
    st.header("🛡️ Vanguard Vault Overview")
    st.success("✅ Zero-Knowledge Architecture: All encryption occurs client-side; ADELL Tech never sees your keys.")
    col1, col2 = st.columns([2,1])
    with col1:
        st.markdown("""
### Operational Modules
* AES-256 Symmetric Locker
* RSA Hybrid Suite
* Diffie-Hellman Exchange
* Steganography
* Integrity Hashing

⚠️ Critical Security Protocol
* All encryption is local
* Recovery Code restores account only, cannot decrypt lost files

👨‍💻 Developer & Command
**Lead Developer:** ADELL Tech
**Status:** Version 2.0
""")
    with col2:
        st.info("💳 Payment Info")
        st.code(BANK_INFO)
        st.markdown(f"[Support via WhatsApp](https://wa.me/{WHATSAPP_NUMBER})")
        st.image("https://img.icons8.com/fluency/100/verified-badge.png")


# ============================================================
# HELP & GUIDE MODULE
# ============================================================
if mode == "🆘 Help & Guide":
    st.header("🛡️ Vanguard Vault — User Guide")
    st.markdown(
        """
Welcome to **Vanguard Vault**, your personal encryption and secure storage system. 
Use this guide to understand all features, how to use them safely, and tips for best practices.
"""
    )

    # ---------------- 1. Getting Started ----------------
    with st.expander("1️⃣ Getting Started"):
        st.markdown("""
**Registering Your Account**
- Go to the Register tab.
- Enter a username, passkey, and accept Terms of Service.
- Save your recovery code. It cannot be recovered later.
- You can download the recovery code as a `.txt` file.

**Logging In**
- Use the Login tab with your username and passkey.
- Forgot your passkey? Use the Recovery Code to reset it.

**Session Timeout**
- Inactivity >30 minutes logs you out automatically.
        """)

    # ---------------- 2. Credits & Paywall ----------------
    with st.expander("2️⃣ Credits & Usage"):
        st.markdown("""
- Each user has a free usage limit (default: 5 operations).
- If limit is reached, a small fee (₦200) unlocks more operations.
- Contact support via WhatsApp with proof to refill credits.
- Admin users have unlimited access.
        """)

    # ---------------- 3. AES Symmetric Locker ----------------
    with st.expander("3️⃣ AES Symmetric Locker"):
        st.markdown("""
**Purpose:** Encrypt/decrypt text, files, and videos using AES-256.

**Steps:**
1. **Key Generation**
   - Generate a random AES key or use your master password.
   - Always save your AES key — losing it means losing your files.

2. **Encrypt Text**
   - Enter plaintext → click Encrypt → copy/download ciphertext.

3. **Decrypt Text**
   - Paste ciphertext → click Decrypt.

4. **File / Video Vault**
   - Upload a file/video → Encrypt → download `.vanguard` file.
   - To decrypt, upload `.vanguard` → provide AES key → download original.

**Tips:**  
- Use the master password consistently for repeatable keys.
- Avoid very large video files to prevent memory issues.
        """)

    # ---------------- 4. RSA Hybrid ----------------
    with st.expander("4️⃣ RSA Hybrid Encryption"):
        st.markdown("""
**Purpose:** Share files securely using hybrid AES + RSA encryption.

**Steps:**
1. **Key Management**
   - Generate a public/private RSA keypair.
   - Keep the private key secret; share only the public key.

2. **Encrypt a File**
   - Paste recipient’s public key.
   - Upload file → Encrypt → download vault & unlock key → send both to recipient.

3. **Decrypt a File**
   - Paste your private key & encrypted unlock key.
   - Upload vault → Decrypt → download original file.
        """)

    # ---------------- 5. Diffie-Hellman ----------------
    with st.expander("5️⃣ Diffie-Hellman Key Exchange"):
        st.markdown("""
**Purpose:** Establish a shared AES key with another operator without sending the key directly.

**Steps:**
1. Generate your DH public key → send to partner.
2. Paste partner’s public key → Calculate shared secret → derived AES key.

**Tip:** Both users must use Vanguard Vault for compatibility.
        """)

    # ---------------- 6. Hashing ----------------
    with st.expander("6️⃣ Hashing & Integrity"):
        st.markdown("""
**Purpose:** Generate secure hashes to verify data integrity.

**Steps:**
1. Select a hash algorithm (SHA-256 recommended).
2. Enter text.
3. Optional: Enable HMAC with a secret key.
4. Click Generate → receive hash digest.
        """)

    # ---------------- 7. Steganography ----------------
    with st.expander("7️⃣ Steganography"):
        st.markdown("""
**Purpose:** Hide encrypted messages in images or videos.

**Hide a Message**
1. Select media type: Image (PNG) or Video (MP4/AVI).
2. Enter secret message & password.
3. Upload cover media → Encrypt & Hide → download stego file.

**Extract a Message**
1. Select media type & enter password.
2. Upload stego file → Extract & Decrypt → view hidden message.

**Tips:**  
- Keep your password safe.
- Large messages may not fit in small images/videos — app will warn you.
        """)

    # ---------------- 8. Support & Contact ----------------
    with st.expander("8️⃣ Support & Contact"):
        st.markdown(f"""
- Use the **Support tab** for help with issues.
- Contact ADELL Tech via WhatsApp: [Click to Chat](https://wa.me/{WHATSAPP_NUMBER})
- Admins monitor support tickets in the Admin Dashboard.
        """)

    # ---------------- 9. Security Notes ----------------
    with st.expander("9️⃣ Security Notes"):
        st.markdown("""
- All encryption is **client-side**; keys are never sent to the server.
- Recovery codes only restore accounts, not encrypted files.
- Always backup your keys, passwords, and recovery codes.
        """)

    st.success("✅ You are ready to use Vanguard Vault safely. Follow these steps and explore each module!")



# ============================================================
# ADMIN DASHBOARD
# ============================================================
if mode == "👑 ADMIN":
    st.header("🛡️ COMMAND CENTER")
    
    # 1. FETCH SYSTEM DATA
    users = conn.table("users").select("*").execute().data
    df_users = pd.DataFrame(users)
    
    # 2. KEY METRICS
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Total Operators", len(df_users))
    with col2:
        total_rev = df_users['payment_count'].sum() * 200
        st.metric("Revenue", f"₦{total_rev:,}")
    with col3:
        # Check for open tickets
        open_tickets = conn.table("support_tickets").select("*").eq("status", "OPEN").execute().data
        st.metric("Open Tickets", len(open_tickets))

    # 3. USER MANAGEMENT & REFILLS
    st.subheader("👤 Operator Management")
    target = st.selectbox("Select Operator to Refill", df_users['username'].tolist())
    if st.button("✅ VERIFY & REFILL (₦200)"):
        curr_p = df_users[df_users['username'] == target]['payment_count'].values[0]
        conn.table("users").update({"op_count": 0, "payment_count": int(curr_p + 1)}).eq("username", target).execute()
        audit(ADMIN_USERNAME, f"REFILLED_{target}")
        st.success(f"Credits restored for {target}.")
        st.rerun()

    # 4. SUPPORT TICKET MONITORING (NEW)
    st.markdown("---")
    st.subheader("📡 Incoming Support Signals")
    
    if open_tickets:
        for t in open_tickets:
            with st.expander(f"Ticket #{t['id']} | From: {t['username']} | Sub: {t['subject']}"):
                st.write(f"**Message:** {t['message']}")
                st.caption(f"Received: {t['timestamp']}")
                
                # Action Buttons
                c1, c2 = st.columns(2)
                with c1:
                    if st.button(f"Mark Resolved #{t['id']}", key=f"res_{t['id']}"):
                        conn.table("support_tickets").update({"status": "RESOLVED"}).eq("id", t['id']).execute()
                        st.success("Ticket cleared.")
                        st.rerun()
                with c2:
                    # Quick link to WhatsApp the user
                    st.link_button("💬 Reply on WhatsApp", f"https://wa.me/{WHATSAPP_NUMBER}?text=Hello%20{t['username']},%20re:%20{t['subject']}")
    else:
        st.success("No pending support tickets. Systems optimal.")
        
# ============================================================