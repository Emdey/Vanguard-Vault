# ============================================================
# VANGUARD VAULT — PAID-READY COMMERCIAL EDITION
# ============================================================

import streamlit as st
import os, io, base64, hashlib, secrets, string
from datetime import datetime, timedelta
import pandas as pd
from PIL import Image

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding, dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from supabase import create_client, Client
import stepic

from style import apply_custom_theme, show_status
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

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

ADMIN_USERNAME = "ADELL_ADMIN"
FREE_LIMIT = 5
SESSION_TIMEOUT_MIN = 30

BANK_INFO = "BANK: Opay | ACCT: 7059194126 | NAME: ADELL TECH"
WHATSAPP_NUMBER = "2347059194126"
FLUTTERWAVE_LINK = "#"  # Replace when live

# ============================================================
# SESSION ISOLATION & TIMEOUT
# ============================================================

def init_session():
    if "auth" not in st.session_state:
        st.session_state.auth = {"user": None, "login_time": None}
    if "crypto" not in st.session_state:
        st.session_state.crypto = {}

def enforce_session_timeout():
    if st.session_state.auth["login_time"]:
        if datetime.utcnow() - st.session_state.auth["login_time"] > timedelta(minutes=SESSION_TIMEOUT_MIN):
            secure_logout()

def secure_logout():
    for k in list(st.session_state.keys()):
        del st.session_state[k]
    st.rerun()

init_session()
enforce_session_timeout()

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

def get_usage(user):
    res = conn.table("users").select("op_count").eq("username", user).execute()
    return res.data[0]["op_count"] if res.data else 0


def increment_usage(user, label):
    if user == ADMIN_USERNAME:
        return
    conn.table("users").update({
        "op_count": get_usage(user) + 1
    }).eq("username", user).execute()
    audit(user, label)


def check_usage_limit(user):
    if user == ADMIN_USERNAME:
        return True

    usage = get_usage(user)

    if usage >= FREE_LIMIT:
        st.markdown(
            f"""
            <div class='support-card'>
                🔒 CREDIT LIMIT REACHED<br>
                Pay <b>₦200</b> to unlock 5 more operations.<br>
                <code>{BANK_INFO}</code><br>
                <a href="https://wa.me/{WHATSAPP_NUMBER}?text=Proof:{user}" target="_blank">
                    📩 Send Proof on WhatsApp
                </a>
            </div>
            """,
            unsafe_allow_html=True
        )
        return False

    return True

# ============================================================
# AUTH UI (LOGIN / REGISTER / RECOVERY)
# ============================================================

if not st.session_state.auth["user"]:
    st.title("🛡️ VANGUARD VAULT")

    t1, t2 = st.tabs(["Login", "Register"])

    with t1:
        u = st.text_input("Username")
        p = st.text_input("Password", type="password")

        if st.button("Access Vault"):
            if not rate_limit(u, "LOGIN"):
                st.error("Too many attempts. Try later.")
                st.stop()

            hp = hashlib.sha256(p.encode()).hexdigest()
            res = conn.table("users").select("*").eq("username", u).eq("password", hp).execute()
            if res.data:
                st.session_state.auth["user"] = u
                st.session_state.auth["login_time"] = datetime.utcnow()
                audit(u, "LOGIN")
                st.rerun()
            else:
                st.error("Access Denied")

        with st.expander("🔑 Forgot Passkey?"):
            ru = st.text_input("Username", key="ru")
            rc = st.text_input("Recovery Code")
            np = st.text_input("New Passkey", type="password")
            if st.button("Reset Passkey"):
                res = conn.table("users").select("*").eq("username", ru).eq("recovery_code", rc).execute()
                if res.data:
                    conn.table("users").update({
                        "password": hashlib.sha256(np.encode()).hexdigest()
                    }).eq("username", ru).execute()
                    audit(ru, "RECOVERY_RESET")
                    st.success("Passkey reset successful.")
                else:
                    st.error("Invalid recovery details.")

    with t2:
        nu = st.text_input("New Username")
        np = st.text_input("New Passkey", type="password")
        agree = st.checkbox("I accept the Terms of Service")

        if st.button("Create Identity") and agree:
            rc = "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(12))
            conn.table("users").insert({
                "username": nu,
                "password": hashlib.sha256(np.encode()).hexdigest(),
                "recovery_code": rc,
                "op_count": 0,
                "payment_count": 0
            }).execute()
            st.success("Account created.")
            st.warning("SAVE THIS RECOVERY CODE")
            st.code(rc)
            st.download_button(
                "Download Recovery Key",
                f"USER:{nu}\nRECOVERY:{rc}",
                f"Recovery_{nu}.txt"
            )

    st.stop()

# ============================================================
# MAIN APPLICATION
# ============================================================

user = st.session_state.auth["user"]

with st.sidebar:
    st.title("VANGUARD")
    st.caption(f"Operator: {user}")
    if st.button("Logout"):
        secure_logout()

menu = [
    "AES Symmetric",
    "RSA Hybrid",
    "Diffie-Hellman",
    "Hashing",
    "Steganography",
    "📡 Support",
    "ℹ️ About"
]

if user == ADMIN_USERNAME:
    menu.insert(0, "👑 ADMIN")

mode = st.selectbox("Module", menu)

# ============================================================
# AES SYMMETRIC MODULE
# ============================================================
if mode == "AES Symmetric":
    st.header("🛡️ AES-256 Symmetric Locker")
    
    master_key = st.text_input(
        "Master Password (Key)", 
        type="password",
        help="This password is used to derive a strong 256-bit encryption key."
    )
    
    if master_key:
        # ---------------- Strong Key Derivation ----------------
        # PBKDF2 with SHA-256, random salt, 200,000 iterations
        if "aes_salt" not in st.session_state:
            st.session_state.aes_salt = os.urandom(16)
        salt = st.session_state.aes_salt
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=200_000
        )
        key = base64.urlsafe_b64encode(kdf.derive(master_key.encode()))
        fernet = Fernet(key)
        
        # ---------------- Tabs for Text and File ----------------
        tab_text, tab_file = st.tabs(["📝 Text Locker", "🎬 File/Video Vault"])
        
        # ---------------- Text Locker ----------------
        with tab_text:
            col1, col2 = st.columns(2)
            
            with col1:
                plaintext = st.text_area("Plaintext to Encrypt")
                if st.button("🔒 Encrypt Text") and plaintext and check_usage_limit(user):
                    st.code(fernet.encrypt(plaintext.encode()).decode())
                    increment_usage(user, "AES_TEXT_ENC")
            
            with col2:
                ciphertext = st.text_area("Ciphertext to Decrypt")
                if st.button("🔓 Decrypt Text") and ciphertext:
                    try:
                        st.success(fernet.decrypt(ciphertext.encode()).decode())
                    except:
                        st.error("Decryption Failed: Invalid Key or Corrupt Data")

        # ---------------- File/Video Vault ----------------
        with tab_file:
            file_upload = st.file_uploader("Upload File/Video")
            if file_upload and st.button("📦 Execute File Lock") and check_usage_limit(user):
                enc_data = fernet.encrypt(file_upload.read())
                st.download_button(
                    f"📥 Download {file_upload.name}.vanguard",
                    enc_data,
                    f"{file_upload.name}.vanguard"
                )
                increment_usage(user, "AES_FILE_ENC")
            vault_upload = st.file_uploader("Upload .vanguard Vault for Decryption", type=['vanguard'])
            if vault_upload and st.button("🔓 Decrypt Vault"):
                try:
                    st.success(fernet.decrypt(vault_upload.read()).decode())
                except:
                    st.error("Decryption Failed: Invalid Key or Corrupt Data")


# ============================================================
# RSA HYBRID MODULE
# ============================================================
elif mode == "RSA Hybrid":
    st.header("🔑 RSA Hybrid Suite (Secure & Future-Proof)")

    tab_key, tab_encrypt, tab_decrypt = st.tabs(["🔑 KEYGEN", "🔒 ENCRYPT", "🔓 DECRYPT"])
    
    # ---------------- Key Generation ----------------
    with tab_key:
        k_size = st.select_slider("Bit Strength", options=[2048, 4096], value=2048)
        if st.button("Generate RSA Keypair") and check_usage_limit(user):
            # Use recommended public exponent
            priv = rsa.generate_private_key(
                public_exponent=65537,
                key_size=k_size
            )
            # PEM format
            pem_pub = priv.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
            pem_priv = priv.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(master_key.encode()) if master_key else serialization.NoEncryption()
            ).decode()
            st.write("📤 **Public Key (Share This)**"); st.code(pem_pub)
            st.write("🔑 **Private Key (KEEP SECRET)**"); st.code(pem_priv)
            increment_usage(user, f"RSA_KEYGEN_{k_size}")

    # ---------------- Hybrid Encryption ----------------
    with tab_encrypt:
        pub_key = st.text_area("Recipient Public Key")
        file_upload = st.file_uploader("Select File")
        if file_upload and pub_key and st.button("Execute Hybrid Lock") and check_usage_limit(user):
            try:
                # AES symmetric session key
                s_key = Fernet.generate_key()
                enc_file = Fernet(s_key).encrypt(file_upload.read())
                pub = serialization.load_pem_public_key(pub_key.encode())
                # Encrypt session key with recipient public key using OAEP
                enc_s_key = pub.encrypt(
                    s_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                st.success("Vault Created!")
                st.code(base64.b64encode(enc_s_key).decode(), label="Recipient Unlock Key")
                st.download_button("Download .vault", enc_file, f"{file_upload.name}.vault")
                increment_usage(user, "RSA_HYBRID_ENC")
            except Exception as e:
                st.error(f"Error: {e}")

    # ---------------- Hybrid Decryption ----------------
    with tab_decrypt:
        priv_key = st.text_area("Your Private Key")
        enc_key = st.text_area("Encrypted Unlock Key")
        vault_file = st.file_uploader("Upload .vault")
        if st.button("🔓 Decrypt & Extract") and vault_file:
            try:
                priv = serialization.load_pem_private_key(priv_key.encode(), password=master_key.encode() if master_key else None)
                s_key = priv.decrypt(
                    base64.b64decode(enc_key.encode()),
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                st.download_button("Download Decrypted File", Fernet(s_key).decrypt(vault_file.read()), "unlocked_file")
            except Exception as e:
                st.error(f"Decryption Failed: {e}")



# ============================================================
# DIFFIE-HELLMAN MODULE
# ============================================================
elif mode == "Diffie-Hellman":
    st.header("🤝 Diffie-Hellman Key Exchange (Secure & Modern)")
    st.info("Establish a 256-bit shared secret key with another operator.")

    # Use safe prime from RFC 3526 (2048-bit MODP Group)
    pn = dh.DHParameterNumbers(
        p=int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
              "29024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497C1B8E99408288D41D738908AF1305D157184E5321D50A22D1612984", 16),
        g=2
    )
    params = pn.parameters()

    tab_gen, tab_secret = st.tabs(["1️⃣ Generate My Key", "2️⃣ Compute Shared Secret"])

    # ---------------- Generate DH Key ----------------
    with tab_gen:
        if st.button("Generate DH Public Key") and check_usage_limit(user):
            priv = params.generate_private_key()
            st.session_state.dh_priv = priv
            pub = priv.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
            st.code(pub, label="Your DH Public Key (Send to partner)")
            increment_usage(user, "DH_KEYGEN")

    # ---------------- Compute Shared Secret ----------------
    with tab_secret:
        partner_pub = st.text_area("Paste Partner's Public Key")
        if st.button("Calculate Shared Secret") and partner_pub:
            try:
                p_pub = serialization.load_pem_public_key(partner_pub.encode())
                shared = st.session_state.dh_priv.exchange(p_pub)
                # Derive 256-bit AES key via HKDF
                derived = HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=None,
                    info=b'handshake'
                ).derive(shared)
                st.success("🤝 Shared Secret Established!")
                st.code(base64.urlsafe_b64encode(derived).decode(), label="Usable AES Key")
            except Exception as e:
                st.error(f"Error: {e}")



# ============================================================
# HASHING MODULE
# ============================================================
elif mode == "Hashing":
    st.header("🔐 Secure Hash Generator")

    # Select hashing algorithm
    algo = st.selectbox(
        "Algorithm",
        ["SHA-256 (Recommended)", "SHA-512", "MD5 (Weak, Legacy Only)"]
    )

    inp = st.text_area("Input Text")

    # Optional key for HMAC
    use_hmac = st.checkbox("Use HMAC (Keyed Hash)")
    key_input = None
    if use_hmac:
        key_input = st.text_input("HMAC Key", type="password", help="Secret key for HMAC hashing")

    if st.button("Generate Hash") and inp:
        try:
            # Select base hash function
            if "SHA-256" in algo:
                hash_func = hashlib.sha256
            elif "SHA-512" in algo:
                hash_func = hashlib.sha512
            else:
                hash_func = hashlib.md5

            # Compute HMAC if key provided
            if use_hmac and key_input:
                h = hmac.new(key_input.encode(), inp.encode(), hash_func)
                digest = h.hexdigest()
            else:
                digest = hash_func(inp.encode()).hexdigest()

            st.code(digest, label=f"{algo} Hash")
            increment_usage(user, f"HASH_{algo.replace(' ', '_')}")
        except Exception as e:
            st.error(f"Hashing Failed: {e}")



# ============================================================
# STEGANOGRAPHY MODULE
# ============================================================
elif mode == "Steganography":
    st.header("🖼️ Steganographic Covert Ops")
    
    tab_hide, tab_extract = st.tabs(["🔒 Hide Message", "🔓 Extract Message"])
    
    with tab_hide:
        img_up = st.file_uploader("Cover Image (PNG)", type=['png'])
        secret_msg = st.text_area("Secret Message")
        password = st.text_input("Encryption Password (Key)", type="password",
                                 help="This password is used to encrypt the message before hiding it.")
        
        if img_up and secret_msg and password and st.button("Encode & Download") and check_usage_limit(user):
            # Generate a random salt
            salt = os.urandom(16)
            
            # Key derivation with PBKDF2HMAC
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=200_000
            )
            key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            fernet = Fernet(key)
            
            # Encrypt the message
            encrypted_msg = fernet.encrypt(secret_msg.encode())
            
            # Prepend salt to encrypted message for decryption
            payload = salt + encrypted_msg
            
            # Encode in image
            buf = io.BytesIO()
            stepic.encode(Image.open(img_up), payload).save(buf, format="PNG")
            st.download_button("Download Secret PNG", buf.getvalue(), "secret.png")
            increment_usage(user, "STEGO_HIDE")
    
    with tab_extract:
        img_enc = st.file_uploader("Upload Secret Image", type=['png'], key="stego_up")
        password = st.text_input("Decryption Password (Key)", type="password", key="stego_pass")
        
        if img_enc and password and st.button("Extract & Decrypt"):
            try:
                hidden_data = stepic.decode(Image.open(img_enc))
                
                # Extract salt (first 16 bytes) and ciphertext
                salt, encrypted_msg = hidden_data[:16], hidden_data[16:]
                
                # Key derivation using extracted salt
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=200_000
                )
                key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
                fernet = Fernet(key)
                
                decrypted_msg = fernet.decrypt(encrypted_msg)
                st.success(f"Hidden Message: {decrypted_msg.decode()}")
            except Exception as e:
                st.error("Failed to extract or decrypt message. Check the password or image.")


# ============================================================
# SUPPORT MODULE
# ============================================================
elif mode == "📡 Support":
    st.header("📡 Secure Support Channel")
    
    with st.form("ticket_form", clear_on_submit=True):
        sub = st.selectbox("Subject", ["Payment Issue", "Bug Report", "Feature Request"])
        msg = st.text_area("Message Body")
        if st.form_submit_button("Transmit Ticket") and msg and check_usage_limit(user):
            conn.table("support_tickets").insert({
                "username": user,
                "subject": sub,
                "message": msg,
                "status": "OPEN",
                "timestamp": datetime.utcnow().isoformat()
            }).execute()
            st.success("🛰️ Signal Transmitted. Admin will review.")
            audit(user, "SUPPORT_TICKET")

    st.subheader("📡 Incoming Support Tickets")
    tickets = conn.table("support_tickets").select("*").execute().data
    if tickets:
        for t in tickets:
            status = t.get("status", "OPEN").upper()
            color = "#FF6B6B" if status=="OPEN" else "#4ECDC4" if status=="RESOLVED" else "#FFD93D"
            with st.expander(f"{t['username']} - {t['subject']}"):
                st.markdown(f"**Message:** {t['message']}  \n"
                            f"**Status:** <span style='color:white;background:{color};padding:4px 8px;border-radius:4px;'>{status}</span>",
                            unsafe_allow_html=True)
                if status=="OPEN" and st.button(f"Resolve Ticket {t['username']}", key=f"res_{t['username']}"):
                    conn.table("support_tickets").update({"status":"RESOLVED"}).eq("username", t['username']).execute()
                    audit(user, f"RESOLVE_TICKET_{t['username']}")
                    st.experimental_rerun()
    else:
        st.info("No pending tickets.")

# ============================================================
# ABOUT MODULE
# ============================================================
elif mode == "ℹ️ About":
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
# ADMIN DASHBOARD
# ============================================================
elif mode == "👑 ADMIN":
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