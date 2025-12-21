import streamlit as st
from st_supabase_connection import SupabaseConnection
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding, dh
import base64
import hashlib
import io
import pandas as pd
from datetime import datetime
import urllib.parse
from style import apply_custom_theme, show_status

# --- SETUP & DATABASE CONNECTION ---
st.set_page_config(page_title="Vanguard Vault | ADELL Tech", layout="wide", page_icon="🛡️")
apply_custom_theme()

# Secure connection to your Supabase backend
st_url = st.secrets["connections"]["supabase"]["url"]
st_key = st.secrets["connections"]["supabase"]["key"]
conn = st.connection("supabase", type=SupabaseConnection, url=st_url, key=st_key)

# --- CONFIGURATION ---
FREE_LIMIT = 5
ADMIN_USERNAME = "ADELL_ADMIN" 
WHATSAPP_NUMBER = "+2347059194126"

# --- UTILITY FUNCTIONS ---
def get_usage(username):
    res = conn.table("users").select("op_count").eq("username", username).execute()
    return res.data[0].get('op_count', 0) if res.data else 0

def check_usage_limit():
    if st.session_state.user == ADMIN_USERNAME: return True 
    count = get_usage(st.session_state.user)
    if count >= FREE_LIMIT:
        st.error(f"🚀 Operation Denied: Free limit of {FREE_LIMIT} reached.")
        st.markdown(f"### 💳 How to Upgrade\n1. Transfer **₦200** to: **YOUR BANK DETAILS**\n2. Send Username **({st.session_state.user})** to Support.")
        return False
    return True

def increment_usage(action_name):
    if st.session_state.user == ADMIN_USERNAME: return
    new_count = get_usage(st.session_state.user) + 1
    conn.table("users").update({"op_count": new_count}).eq("username", st.session_state.user).execute()
    add_to_history(action_name, f"Op {new_count}/{FREE_LIMIT}")

def check_user(username, password):
    hashed_pw = hashlib.sha256(password.encode()).hexdigest()
    res = conn.table("users").select("*").eq("username", username).eq("password", hashed_pw).execute()
    return len(res.data) > 0

def add_user(username, password):
    hashed_pw = hashlib.sha256(password.encode()).hexdigest()
    try:
        conn.table("users").insert({"username": username, "password": hashed_pw, "op_count": 0}).execute()
        return True
    except: return False

def add_to_history(action, detail):
    timestamp = datetime.now().strftime("%H:%M:%S")
    st.session_state.vault_history.insert(0, f"[{timestamp}] {action}: {detail}")

# --- INITIALIZE SESSION STATES ---
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.user = None

states = {
    'private_key_pem': None, 'public_key_pem': None, 
    'sym_enc_data': None, 'asym_enc_data': None, 'asym_enc_key': None,
    'dh_private_key': None, 'dh_public_pem': None, 'vault_history': []
}
for key, val in states.items():
    if key not in st.session_state: st.session_state[key] = val

# --- APP ROUTING ---
if not st.session_state.logged_in:
    st.title("🛡️ VANGUARD VAULT")
    t_login, t_signup = st.tabs(["🔑 LOGIN", "👤 REGISTER"])
    with t_login:
        u = st.text_input("Username")
        p = st.text_input("Password", type="password")
        if st.button("Access Vault"):
            if check_user(u, p):
                st.session_state.logged_in, st.session_state.user = True, u
                add_to_history("Login", u)
                st.rerun()
            else: st.error("Invalid Credentials.")
    with t_signup:
        nu = st.text_input("New Username")
        np = st.text_input("New Password", type="password")
        if st.button("Register Account"):
            if add_user(nu, np): st.success("Created! Please Login.")
            else: st.error("Username taken.")
else:
    with st.sidebar:
        show_status()
        st.markdown("<h2 style='color: #00d4ff;'>ADELL TECH</h2>", unsafe_allow_html=True)
        ops_done = get_usage(st.session_state.user)
        
        # Upgrade Animation
        if ops_done == 0 and st.session_state.vault_history and any("Op" in h for h in st.session_state.vault_history):
            st.balloons()
            st.success("✅ Account Upgraded!")
            
        st.progress(min(ops_done / FREE_LIMIT, 1.0))
        st.caption(f"Usage: {ops_done} / {FREE_LIMIT}")
        
        msg = urllib.parse.quote(f"Upgrade request for: {st.session_state.user}")
        st.link_button("💬 Chat with Support", f"https://wa.me/{WHATSAPP_NUMBER}?text={msg}")
        
        # Default menu options with "About" as first
        menu_options = ["📜 About Vanguard", "Symmetric (AES-256)", "Asymmetric (RSA)", "Diffie-Hellman Exchange", "Hashing & Integrity"]
        
        # Admin gets dashboard at top
        if st.session_state.user == ADMIN_USERNAME: 
            menu_options.insert(0, "👑 ADMIN DASHBOARD")
            
        mode = st.selectbox("SYSTEM SELECTION", menu_options)
        
        st.divider()
        if st.button("🗑️ Clear Vault History"):
            st.session_state.vault_history = []
            st.toast("History Purged")
            
        if st.button("🔒 LOGOUT"):
            st.session_state.logged_in = False
            st.rerun()

    # --- MODE ROUTING ---
    
    # 0. ABOUT PAGE (Default)
    if mode == "📜 About Vanguard":
        st.title("🛡️ Vanguard Vault")
        st.markdown(f"Welcome, **{st.session_state.user}**. Secure your communication with military-grade protocols.")
        
        col1, col2 = st.columns(2)
        with col1:
            st.info("### 🔐 Encryption Tools\n- **AES-256**: For local secure storage.\n- **RSA-2048**: For secure identity exchange.")
        with col2:
            st.info("### 📡 Exchange & Integrity\n- **Diffie-Hellman**: Shared secret generation.\n- **SHA-256**: File & text tampering checks.")
        
        st.subheader("📋 Recent Vault Activity")
        if st.session_state.vault_history:
            for item in st.session_state.vault_history[:10]:
                st.write(item)
        else:
            st.caption("No recent activity.")

    # 1. ADMIN DASHBOARD
    elif mode == "👑 ADMIN DASHBOARD":
        st.title("👑 Admin Control Center")
        users_data = conn.table("users").select("username, op_count").execute()
        df = pd.DataFrame(users_data.data)
        st.table(df)
        u_to_fix = st.selectbox("Select User to Reset", df['username'].tolist())
        if st.button("Reset Operations (Upgrade User)"):
            conn.table("users").update({"op_count": 0}).eq("username", u_to_fix).execute()
            st.success(f"User {u_to_fix} has been reset!")
            st.rerun()

    # 2. AES-256 SYMMETRIC
    elif mode == "Symmetric (AES-256)":
        st.header("AES-256 Text Encryption")
        pwd = st.text_input("Master Password", type="password")
        msg_to_enc = st.text_area("Message to Encrypt", height=150)
        
        if st.button("Encrypt Message") and check_usage_limit():
            if pwd and msg_to_enc:
                key = base64.urlsafe_b64encode(hashlib.sha256(pwd.encode()).digest())
                st.session_state.sym_enc_data = Fernet(key).encrypt(msg_to_enc.encode())
                increment_usage("AES-MSG")
                st.success("Message Secured!")
                st.code(st.session_state.sym_enc_data.decode())

    # 3. ASYMMETRIC (RSA)
    elif mode == "Asymmetric (RSA)":
        st.header("RSA-2048 Asymmetric Messaging")
        t1, t2 = st.tabs(["🔑 Key Management", "🔒 Secure Messaging"])
        
        with t1:
            if st.button("Generate RSA Pair") and check_usage_limit():
                priv = rsa.generate_private_key(65537, 2048)
                st.session_state.private_key_pem = priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
                st.session_state.public_key_pem = priv.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
                increment_usage("RSA-KEY")
            
            if st.session_state.private_key_pem:
                st.download_button("📥 Download Private Key", st.session_state.private_key_pem, "private.pem")
                st.download_button("📥 Download Public Key", st.session_state.public_key_pem, "public.pem")
        
        with t2:
            pub_key_input = st.file_uploader("Receiver's Public Key (.pem)")
            secret_msg = st.text_area("Message for Receiver")
            
            if pub_key_input and secret_msg and st.button("RSA Encrypt") and check_usage_limit():
                pub_obj = serialization.load_pem_public_key(pub_key_input.read())
                aes_key = Fernet.generate_key()
                st.session_state.asym_enc_data = Fernet(aes_key).encrypt(secret_msg.encode())
                increment_usage("RSA-ENC")
                st.success("Message Encrypted.")
                st.code(base64.b64encode(st.session_state.asym_enc_data).decode())

    # 4. DIFFIE-HELLMAN
    elif mode == "Diffie-Hellman Exchange":
        st.header("Diffie-Hellman Key Exchange")
        if st.button("Generate DH Public Component") and check_usage_limit():
            pn = dh.DHParameterNumbers(p=int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF", 16), g=2)
            priv = pn.parameters().generate_private_key()
            st.session_state.dh_public_pem = priv.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
            increment_usage("DH-KEY")
        
        if st.session_state.dh_public_pem:
            st.code(st.session_state.dh_public_pem.decode())
            st.download_button("💾 Download DH Key", st.session_state.dh_public_pem, "dh_pub.pem")

    # 5. HASHING
    elif mode == "Hashing & Integrity":
        st.header("SHA-256 Hashing")
        h_input = st.text_area("Text to Hash")
        if h_input and st.button("Generate Hash") and check_usage_limit():
            result = hashlib.sha256(h_input.encode()).hexdigest()
            st.code(result, language="text")
            increment_usage("HASH")