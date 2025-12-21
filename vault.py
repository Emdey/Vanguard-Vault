import streamlit as st
from st_supabase_connection import SupabaseConnection
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding, dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import base64
import hashlib
import io
import pandas as pd
from datetime import datetime
import urllib.parse
from PIL import Image
from style import apply_custom_theme, show_status

# --- SETUP & DATABASE CONNECTION ---
st.set_page_config(page_title="Vanguard Vault | ADELL Tech", layout="wide", page_icon="🛡️")
apply_custom_theme()

# Secure Connection with Error Handling
try:
    st_url = st.secrets["connections"]["supabase"]["url"]
    st_key = st.secrets["connections"]["supabase"]["key"]
    conn = st.connection("supabase", type=SupabaseConnection, url=st_url, key=st_key)
except Exception as e:
    st.error("Database connection failed. Check your Streamlit Secrets.")
    st.stop()

# --- CONFIGURATION ---
FREE_LIMIT = 10 
ADMIN_USERNAME = "ADELL_ADMIN" 

# --- UTILITY FUNCTIONS ---
def get_usage(username):
    try:
        res = conn.table("users").select("op_count").eq("username", username).execute()
        return res.data[0].get('op_count', 0) if res.data else 0
    except:
        return 0

def check_usage_limit():
    if st.session_state.get('user') == ADMIN_USERNAME: return True 
    count = get_usage(st.session_state.get('user'))
    if count >= FREE_LIMIT:
        st.error(f"🚀 Operation Denied: Free limit reached.")
        return False
    return True

def increment_usage(action_name):
    if st.session_state.get('user') == ADMIN_USERNAME: return
    current_user = st.session_state.get('user')
    new_count = get_usage(current_user) + 1
    conn.table("users").update({"op_count": new_count}).eq("username", current_user).execute()
    add_to_history(action_name, f"Op {new_count}/{FREE_LIMIT}")

def add_to_history(action, detail):
    timestamp = datetime.now().strftime("%H:%M:%S")
    if 'vault_history' not in st.session_state:
        st.session_state.vault_history = []
    st.session_state.vault_history.insert(0, f"[{timestamp}] {action}: {detail}")

def check_password_strength(password):
    strength = 0
    if len(password) >= 8: strength += 1
    if any(c.isupper() for c in password): strength += 1
    if any(c.isdigit() for c in password): strength += 1
    if any(c in "!@#$%^&*()_+" for c in password): strength += 1
    return strength

def generate_qr(data):
    encoded_data = urllib.parse.quote(data)
    return f"https://api.qrserver.com/v1/create-qr-code/?size=250x250&data={encoded_data}"

# --- STEGANOGRAPHY LOGIC ---
def encode_image(img, secret_data):
    encoded = img.copy()
    width, height = img.size
    binary_secret = ''.join(format(ord(i), '08b') for i in secret_data) + '1111111111111110'
    data_index = 0
    pixels = encoded.load()
    for y in range(height):
        for x in range(width):
            r, g, b = pixels[x, y]
            if data_index < len(binary_secret):
                r = r & ~1 | int(binary_secret[data_index]); data_index += 1
            if data_index < len(binary_secret):
                g = g & ~1 | int(binary_secret[data_index]); data_index += 1
            if data_index < len(binary_secret):
                b = b & ~1 | int(binary_secret[data_index]); data_index += 1
            pixels[x, y] = (r, g, b)
            if data_index >= len(binary_secret): return encoded
    return encoded

def decode_image(img):
    binary_data = ""
    pixels = img.load()
    for y in range(img.height):
        for x in range(img.width):
            r, g, b = pixels[x, y]
            binary_data += str(r & 1) + str(g & 1) + str(b & 1)
    all_bytes = [binary_data[i:i+8] for i in range(0, len(binary_data), 8)]
    decoded_text = ""
    for byte in all_bytes:
        char = chr(int(byte, 2))
        if decoded_text[-2:] == 'ÿþ': break
        decoded_text += char
    return decoded_text[:-2]

# --- INITIALIZE SESSION ---
if 'logged_in' not in st.session_state: st.session_state.logged_in = False
if 'vault_history' not in st.session_state: st.session_state.vault_history = []
if 'dh_private_key' not in st.session_state: st.session_state.dh_private_key = None
if 'user' not in st.session_state: st.session_state.user = None

# --- AUTHENTICATION ---
if not st.session_state.logged_in:
    st.title("🛡️ VANGUARD VAULT")
    t_login, t_signup = st.tabs(["🔑 LOGIN", "👤 REGISTER"])
    with t_login:
        u = st.text_input("Username")
        p = st.text_input("Password", type="password")
        if st.button("Access Vault"):
            hashed_pw = hashlib.sha256(p.encode()).hexdigest()
            res = conn.table("users").select("*").eq("username", u).eq("password", hashed_pw).execute()
            if len(res.data) > 0:
                st.session_state.logged_in = True
                st.session_state.user = u
                add_to_history("Login", u)
                st.rerun()
            else: st.error("Invalid Credentials.")
    with t_signup:
        nu = st.text_input("New Username")
        np = st.text_input("New Password", type="password")
        if np:
            score = check_password_strength(np)
            st.progress(score / 4)
            st.caption(f"Security Level: {score}/4")
        if st.button("Register"):
            hpw = hashlib.sha256(np.encode()).hexdigest()
            try:
                conn.table("users").insert({"username": nu, "password": hpw, "op_count": 0}).execute()
                st.success("Account Created!")
            except: st.error("Username taken or error.")

else:
    with st.sidebar:
        show_status()
        st.markdown("<h2 style='color: #00f2ff;'>ADELL TECH</h2>", unsafe_allow_html=True)
        ops = get_usage(st.session_state.user)
        st.progress(min(ops / FREE_LIMIT, 1.0))
        st.caption(f"Capacity: {ops} / {FREE_LIMIT}")
        
        menu = ["📜 About", "Symmetric (AES)", "Asymmetric (RSA)", "Diffie-Hellman", "Steganography", "Hashing"]
        if st.session_state.user == ADMIN_USERNAME: menu.insert(0, "👑 ADMIN")
        mode = st.selectbox("SYSTEM SELECTION", menu)
        
        if st.button("🔒 LOGOUT"):
            st.session_state.logged_in = False
            st.session_state.user = None
            st.rerun()

    # --- MODE: ABOUT ---
    if mode == "📜 About":
        st.header("🛡️ System Dashboard")
        st.info("Vanguard Vault: Multi-Layer Cryptographic Suite Active.")
        st.subheader("📋 Recent History")
        for item in st.session_state.vault_history[:10]: st.write(item)

    # --- MODE: ADMIN ---
    elif mode == "👑 ADMIN":
        st.header("Admin Control Panel")
        res = conn.table("users").select("username, op_count").execute()
        df = pd.DataFrame(res.data)
        st.table(df)
        target = st.selectbox("Select User to Reset", df['username'].tolist())
        if st.button("Reset Operations"):
            conn.table("users").update({"op_count": 0}).eq("username", target).execute()
            st.success(f"Reset {target}")
            st.rerun()

    # --- MODE: SYMMETRIC ---
    elif mode == "Symmetric (AES)":
        st.header("AES-256 Multi-Locker")
        
        pwd = st.text_input("Master Password", type="password")
        if pwd:
            key = base64.urlsafe_b64encode(hashlib.sha256(pwd.encode()).digest())
            task = st.radio("Target Type", ["Text", "File/Video"])
            
            if task == "Text":
                txt = st.text_area("Input Text")
                if st.button("Process Text") and check_usage_limit():
                    st.code(Fernet(key).encrypt(txt.encode()).decode())
                    increment_usage("AES-TEXT")
            else:
                up_f = st.file_uploader("Upload File (Video, Image, PDF)")
                if up_f:
                    f_bytes = up_f.read()
                    c1, c2 = st.columns(2)
                    with c1:
                        if st.button("Lock File"):
                            enc = Fernet(key).encrypt(f_bytes)
                            st.download_button("Download Encrypted", enc, f"{up_f.name}.vault")
                            increment_usage("AES-FILE")
                    with c2:
                        if st.button("Unlock File"):
                            try:
                                dec = Fernet(key).decrypt(f_bytes)
                                st.download_button("Download Decrypted", dec, f"RESTORED_{up_f.name.replace('.vault','')}")
                                increment_usage("AES-DECRYPT")
                            except: st.error("Incorrect Password or Corrupted File.")

    # --- MODE: RSA ---
    elif mode == "Asymmetric (RSA)":
        st.header("RSA Protocols")
        
        t1, t2 = st.tabs(["Keys", "Operations"])
        with t1:
            bits = st.select_slider("Strength", [1024, 2048, 4096], 2048)
            if st.button("Generate Pair") and check_usage_limit():
                priv = rsa.generate_private_key(65537, bits)
                st.session_state.rsa_pub = priv.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
                st.session_state.rsa_priv = priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
                increment_usage("RSA-GEN")
            if 'rsa_pub' in st.session_state:
                st.code(st.session_state.rsa_pub)
                st.image(generate_qr(st.session_state.rsa_pub))
        
        with t2:
            key_input = st.file_uploader("Upload Key (.pem)")
            target_f = st.file_uploader("Upload Target (Video/File)")
            action = st.radio("Mode", ["Encrypt (Public Key)", "Decrypt (Private Key)"])
            
            if key_input and target_f and st.button("Execute RSA"):
                if action == "Encrypt (Public Key)":
                    pub_obj = serialization.load_pem_public_key(key_input.read())
                    session_key = Fernet.generate_key()
                    esk = pub_obj.encrypt(session_key, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
                    edat = Fernet(session_key).encrypt(target_f.read())
                    st.download_button("Download RSA Package", esk + b"||SEP||" + edat, f"{target_f.name}.rsa")
                    increment_usage("RSA-ENC")
                else:
                    try:
                        priv_obj = serialization.load_pem_private_key(key_input.read(), None)
                        raw = target_f.read()
                        esk, edat = raw.split(b"||SEP||")
                        session_key = priv_obj.decrypt(esk, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
                        st.download_button("Recover Original", Fernet(session_key).decrypt(edat), "RESTORED_FILE")
                        increment_usage("RSA-DEC")
                    except: st.error("Decryption Failed. Check your Private Key.")

    # --- MODE: DH ---
    elif mode == "Diffie-Hellman":
        st.header("Diffie-Hellman Key Exchange")
        
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Generate My Component"):
                param = dh.DHParameterNumbers(p=int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF", 16), g=2)
                st.session_state.dh_private_key = param.parameters().generate_private_key()
                st.session_state.dh_pub_pem = st.session_state.dh_private_key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
                increment_usage("DH-GEN")
            if 'dh_pub_pem' in st.session_state: st.code(st.session_state.dh_pub_pem)
        
        with col2:
            peer_f = st.file_uploader("Upload Peer Component")
            if peer_f and st.session_state.dh_private_key:
                peer_pub = serialization.load_pem_public_key(peer_f.read())
                shared = st.session_state.dh_private_key.exchange(peer_pub)
                st.session_state.dh_aes_key = base64.urlsafe_b64encode(HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'dh').derive(shared))
                st.success("Secure Channel Established")

        if 'dh_aes_key' in st.session_state:
            target_media = st.file_uploader("Upload Media to Tunnel")
            if target_media and st.button("Push through Tunnel"):
                enc_media = Fernet(st.session_state.dh_aes_key).encrypt(target_media.read())
                st.download_button("Download Tunneled File", enc_media, f"{target_media.name}.vault")
                increment_usage("DH-PUSH")

    # --- MODE: STEGANOGRAPHY ---
    elif mode == "Steganography":
        st.header("Image Stealth")
        
        s1, s2 = st.tabs(["Hide", "Reveal"])
        with s1:
            img_f = st.file_uploader("Cover Image (PNG/JPG)")
            sec_t = st.text_input("Secret Text")
            if img_f and sec_t and st.button("Embed"):
                res = encode_image(Image.open(img_f).convert('RGB'), sec_t)
                buf = io.BytesIO(); res.save(buf, format="PNG")
                st.image(res); st.download_button("Download Stealth Image", buf.getvalue(), "stego.png")
                increment_usage("STEGO-HIDE")
        with s2:
            steg = st.file_uploader("Stego File")
            if steg and st.button("Reveal"): 
                st.info(decode_image(Image.open(steg).convert('RGB')))
                increment_usage("STEGO-REVEAL")

    # --- MODE: HASHING ---
    elif mode == "Hashing":
        st.header("Digital Integrity")
        
        raw_input = st.file_uploader("Upload any file to Hash")
        if raw_input and st.button("Hash File"):
            h = hashlib.sha256(raw_input.read()).hexdigest()
            st.code(h); st.image(generate_qr(h))
            increment_usage("HASH")