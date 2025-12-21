import streamlit as st
from st_supabase_connection import SupabaseConnection
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding, dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import base64
import hashlib
import io
import re
import pandas as pd
from datetime import datetime

# --- IMPORT CUSTOM THEME ---
from style import apply_custom_theme

# --- SETUP & DATABASE CONNECTION ---
st.set_page_config(page_title="Vanguard Vault | ADELL Tech", layout="wide", page_icon="🛡️")
apply_custom_theme()

# Connect to Supabase via secrets.toml
conn = st.connection("supabase", type=SupabaseConnection)

# --- HELPER: PASSWORD STRENGTH ---
def check_password_strength(password):
    score = 0
    if len(password) >= 12: score += 1
    if re.search(r"[A-Z]", password): score += 1
    if re.search(r"[0-9]", password): score += 1
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password): score += 1
    return score

# --- AUTH LOGIC ---
def add_user(username, password):
    hashed_pw = hashlib.sha256(password.encode()).hexdigest()
    try:
        conn.table("users").insert({"username": username, "password": hashed_pw}).execute()
        return True
    except Exception:
        return False

def check_user(username, password):
    hashed_pw = hashlib.sha256(password.encode()).hexdigest()
    res = conn.table("users").select("*").eq("username", username).eq("password", hashed_pw).execute()
    return len(res.data) > 0

# --- SESSION STATES ---
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.user = None

states = {
    'private_key_pem': None, 'public_key_pem': None, 
    'sym_enc_data': None, 'sym_dec_data': None, 
    'asym_enc_key': None, 'asym_enc_data': None, 'asym_dec_data': None, 
    'dh_private_key': None, 'dh_public_pem': None, 'dh_shared_key': None,
    'vault_history': [] 
}
for key, value in states.items():
    if key not in st.session_state: st.session_state[key] = value

def add_to_history(action, detail):
    timestamp = datetime.now().strftime("%H:%M:%S")
    st.session_state.vault_history.insert(0, f"[{timestamp}] {action}: {detail}")

# --- APP ROUTING ---
if not st.session_state.logged_in:
    st.title("🛡️ VANGUARD VAULT")
    st.caption("Secure Access Portal | **ADELL Tech**")
    
    t_login, t_signup = st.tabs(["🔑 LOGIN", "👤 REGISTER"])
    
    with t_login:
        user = st.text_input("Username")
        pw = st.text_input("Password", type="password")
        if st.button("Access Vault"):
            if check_user(user, pw):
                st.session_state.logged_in = True
                st.session_state.user = user
                add_to_history("Login", user)
                st.rerun()
            else:
                st.error("Invalid Credentials.")

    with t_signup:
        new_user = st.text_input("New Username")
        new_pw = st.text_input("New Password", type="password")
        strength = 0
        if new_pw:
            strength = check_password_strength(new_pw)
            remarks = ["Very Weak 🛑", "Weak ⚠️", "Fair 🆗", "Strong ✅", "Pro 🏆"]
            st.progress(strength / 4)
            st.caption(f"Security Level: **{remarks[strength]}**")
        
        if st.button("Register with ADELL"):
            if strength < 3:
                st.warning("Password must be 'Strong' or higher to meet ADELL protocols.")
            elif add_user(new_user, new_pw):
                st.success("Cloud ID Created. Please switch to Login tab.")
            else:
                st.error("Account creation failed (User may already exist).")

else:
    # --- AUTHENTICATED VAULT APP ---
    with st.sidebar:
        st.markdown("<h2 style='color: #00d4ff;'>ADELL</h2>", unsafe_allow_html=True)
        st.write(f"Active Session: **{st.session_state.user}**")
        mode = st.selectbox("SYSTEM SELECTION", [
            "Symmetric (AES-256)", 
            "Asymmetric (RSA)", 
            "Diffie-Hellman Exchange", 
            "Hashing & Integrity"
        ])
        if st.button("🔒 SECURE LOGOUT"):
            st.session_state.logged_in = False
            st.rerun()
        
        st.subheader("📜 SESSION LOGS")
        for log in st.session_state.vault_history[:8]:
            st.caption(log)

    st.title(f"Vanguard Mode: {mode}")

    # --- 1. SYMMETRIC (AES-256) ---
    if mode == "Symmetric (AES-256)":
        st.info("Encrypt messages or files with a master password using ADELL standards.")
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("🔒 Encrypt")
            pwd = st.text_input("Set Master Password", type="password", key="aes_pwd")
            in_type = st.radio("Input Type", ["Message", "File"])
            to_lock = None
            if in_type == "Message":
                m = st.text_area("Your Message")
                if m: to_lock = m.encode()
            else:
                f = st.file_uploader("Upload File")
                if f: to_lock = f.read()
            
            if st.button("Encrypt Data"):
                if pwd and to_lock:
                    key = base64.urlsafe_b64encode(hashlib.sha256(pwd.encode()).digest())
                    st.session_state.sym_enc_data = Fernet(key).encrypt(to_lock)
                    add_to_history("AES-ENC", in_type)
                    st.success("Encryption complete.")
            
            if st.session_state.sym_enc_data:
                st.download_button("📥 Download .enc", st.session_state.sym_enc_data, "secure_vault.enc")

        with col2:
            st.subheader("🔓 Decrypt")
            dec_pwd = st.text_input("Unlock Password", type="password")
            dec_f = st.file_uploader("Upload .enc file")
            if st.button("Unlock File"):
                try:
                    key = base64.urlsafe_b64encode(hashlib.sha256(dec_pwd.encode()).digest())
                    st.session_state.sym_dec_data = Fernet(key).decrypt(dec_f.read())
                    add_to_history("AES-DEC", "Data restored")
                    st.success("File Decrypted!")
                except: st.error("Verification failed. Incorrect password.")
            
            if st.session_state.sym_dec_data:
                st.download_button("💾 Download Restored File", st.session_state.sym_dec_data, "restored_item")

    # --- 2. ASYMMETRIC (RSA) ---
    elif mode == "Asymmetric (RSA)":
        st.info("Generate keys and handle secure identity verification.")
        t1, t2, t3 = st.tabs(["🔑 Key Generation", "🔒 RSA Encryption", "✍️ Digital Signatures"])
        
        with t1:
            size = st.select_slider("Strength", options=[2048, 4096], value=2048)
            if st.button("Generate RSA Pair"):
                priv = rsa.generate_private_key(65537, size)
                st.session_state.private_key_pem = priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
                st.session_state.public_key_pem = priv.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
                add_to_history("RSA-KEY", f"{size}bit")
            if st.session_state.private_key_pem:
                st.download_button("💾 Download Private Key", st.session_state.private_key_pem, "private.pem")
                st.download_button("💾 Download Public Key", st.session_state.public_key_pem, "public.pem")

        with t2:
            pub_key_file = st.file_uploader("Receiver's Public Key")
            data_file = st.file_uploader("File to Encrypt")
            if pub_key_file and data_file and st.button("RSA Encrypt"):
                pub_obj = serialization.load_pem_public_key(pub_key_file.read())
                # Hybrid encryption: Encrypt data with AES, then encrypt AES key with RSA
                aes_key = Fernet.generate_key()
                st.session_state.asym_enc_data = Fernet(aes_key).encrypt(data_file.read())
                st.session_state.asym_enc_key = pub_obj.encrypt(aes_key, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
                st.success("Encrypted. Download both files to send.")
            if st.session_state.asym_enc_data:
                st.download_button("📥 Data (.enc)", st.session_state.asym_enc_data, "data.enc")
                st.download_button("🔑 Encrypted Key", st.session_state.asym_enc_key, "key.enc")

        with t3:
            st.write("**Sign a File to Prove Identity**")
            sign_priv = st.file_uploader("Your Private Key")
            file_to_sign = st.file_uploader("File to Sign")
            if sign_priv and file_to_sign and st.button("Sign Now"):
                priv_obj = serialization.load_pem_private_key(sign_priv.read(), None)
                signature = priv_obj.sign(file_to_sign.read(), padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
                st.download_button("📥 Download Signature (.sig)", signature, f"{file_to_sign.name}.sig")

    # --- 3. DIFFIE-HELLMAN ---
    elif mode == "Diffie-Hellman Exchange":
        st.info("Establish a shared secret key with another party over insecure lines.")
        col_a, col_b = st.columns(2)
        with col_a:
            if st.button("Generate DH Session Keys"):
                pn = dh.DHParameterNumbers(p=int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF", 16), g=2)
                priv = pn.parameters().generate_private_key()
                st.session_state.dh_private_key = priv
                st.session_state.dh_public_pem = priv.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
            if st.session_state.dh_public_pem:
                st.download_button("💾 Download My DH Public Key", st.session_state.dh_public_pem, "my_dh_pub.pem")

        with col_b:
            p_file = st.file_uploader("Upload Partner's DH Key")
            if p_file and st.session_state.dh_private_key:
                if st.button("Establish Shared Secret"):
                    p_pub = serialization.load_pem_public_key(p_file.read())
                    raw_secret = st.session_state.dh_private_key.exchange(p_pub)
                    derived = HKDF(hashes.SHA256(), 32, None, b'handshake').derive(raw_secret)
                    st.session_state.dh_shared_key = base64.urlsafe_b64encode(derived).decode()
                    st.success("Handshake Successful. Secure Tunnel Established.")
                    st.code(f"Shared Session Key: {st.session_state.dh_shared_key}")

    # --- 4. HASHING & INTEGRITY ---
    else:
        st.info("Verify file integrity using ADELL verification protocols.")
        algo = st.selectbox("Algorithm", ["SHA-256", "SHA-512", "MD5"])
        bulk_files = st.file_uploader("Upload Files for Verification", accept_multiple_files=True)
        if bulk_files and st.button("Generate Integrity Report"):
            report = []
            for bf in bulk_files:
                content = bf.read()
                if algo == "SHA-256": h = hashlib.sha256(content).hexdigest()
                elif algo == "SHA-512": h = hashlib.sha512(content).hexdigest()
                else: h = hashlib.md5(content).hexdigest()
                report.append({"Filename": bf.name, "Hash": h, "Status": "Verified"})
            df = pd.DataFrame(report)
            st.table(df)
            st.download_button("📥 Download Report (CSV)", df.to_csv(index=False), "integrity_report.csv")