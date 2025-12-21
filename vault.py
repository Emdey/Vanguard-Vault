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

# --- SETUP & DATABASE CONNECTION ---
st.set_page_config(page_title="Vanguard Vault | ADELL Tech", layout="wide", page_icon="🛡️")

# Attempt to load your custom style module
try:
    from style import apply_custom_theme, show_status
    apply_custom_theme()
except:
    st.markdown("<style>.stButton>button {background-color: #00f2ff; color: black;}</style>", unsafe_allow_html=True)

# Secure Connection
try:
    st_url = st.secrets["connections"]["supabase"]["url"]
    st_key = st.secrets["connections"]["supabase"]["key"]
    conn = st.connection("supabase", type=SupabaseConnection, url=st_url, key=st_key)
except Exception as e:
    st.error("Database connection failed. Check your Streamlit Secrets.")
    st.stop()

# --- CONFIGURATION ---
FREE_LIMIT = 5 
ADMIN_USERNAME = "ADELL_ADMIN" 

# --- EDIT THESE DETAILS ---
BANK_NAME = "Your Bank Name"
ACCOUNT_NO = "0123456789"
ACCOUNT_NAME = "ADELL TECH"
WHATSAPP_NUMBER = "234XXXXXXXXXX" # e.g., 2348123456789

# --- UTILITY FUNCTIONS ---
def get_usage(username):
    try:
        res = conn.table("users").select("op_count").eq("username", username).execute()
        return res.data[0].get('op_count', 0) if res.data else 0
    except: return 0

def check_usage_limit():
    if st.session_state.get('user') == ADMIN_USERNAME: return True 
    count = get_usage(st.session_state.get('user'))
    if count >= FREE_LIMIT:
        st.error(f"🚨 **CAPACITY FINISHED ({count}/{FREE_LIMIT})**")
        st.markdown(f"""
        <div style="background-color: #1e1e1e; padding: 20px; border-radius: 10px; border: 2px solid #ff4b4b;">
            <h3 style="color: #ff4b4b; margin-top: 0;">Access Denied</h3>
            <p>Please pay <b>₦200</b> to get 5 more operations:</p>
            <p style="font-family: monospace; background: #000; padding: 10px; border-left: 5px solid #00f2ff;">
                Bank: {BANK_NAME}<br>
                Acct: {ACCOUNT_NO}<br>
                Name: {ACCOUNT_NAME}
            </p>
            <a href="https://wa.me/{WHATSAPP_NUMBER}?text=Payment%20made%20for%20Vault%20User:%20{st.session_state.user}" 
               target="_blank" style="display: inline-block; padding: 10px; background-color: #25D366; color: white; text-decoration: none; border-radius: 5px; font-weight: bold;">
               ✅ Send Proof to Admin (WhatsApp)
            </a>
        </div>
        """, unsafe_allow_html=True)
        return False
    return True

def increment_usage(action_name):
    if st.session_state.get('user') == ADMIN_USERNAME: return
    current_user = st.session_state.get('user')
    new_count = get_usage(current_user) + 1
    conn.table("users").update({"op_count": new_count}).eq("username", current_user).execute()
    # History Tracking
    timestamp = datetime.now().strftime("%H:%M:%S")
    if 'vault_history' not in st.session_state: st.session_state.vault_history = []
    st.session_state.vault_history.insert(0, f"[{timestamp}] {action_name}: Done")

def generate_qr(data):
    # This generates a URL for the QR code image
    encoded_data = urllib.parse.quote(str(data))
    return f"https://api.qrserver.com/v1/create-qr-code/?size=250x250&data={encoded_data}"

# --- CRYPTO LOGIC ---
def encode_image(img, secret_data):
    encoded = img.copy()
    binary_secret = ''.join(format(ord(i), '08b') for i in secret_data) + '1111111111111110'
    data_index = 0
    pixels = encoded.load()
    for y in range(img.height):
        for x in range(img.width):
            r, g, b = pixels[x, y]
            if data_index < len(binary_secret): r = r & ~1 | int(binary_secret[data_index]); data_index += 1
            if data_index < len(binary_secret): g = g & ~1 | int(binary_secret[data_index]); data_index += 1
            if data_index < len(binary_secret): b = b & ~1 | int(binary_secret[data_index]); data_index += 1
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
        try:
            char = chr(int(byte, 2))
            if decoded_text[-2:] == 'ÿþ': break
            decoded_text += char
        except: break
    return decoded_text[:-2]

# --- APP FLOW ---
if 'logged_in' not in st.session_state: st.session_state.logged_in = False

if not st.session_state.logged_in:
    st.title("🛡️ VANGUARD VAULT")
    t1, t2 = st.tabs(["LOGIN", "REGISTER"])
    with t1:
        u = st.text_input("Username")
        p = st.text_input("Password", type="password")
        if st.button("Login"):
            hpw = hashlib.sha256(p.encode()).hexdigest()
            res = conn.table("users").select("*").eq("username", u).eq("password", hpw).execute()
            if len(res.data) > 0:
                st.session_state.logged_in = True
                st.session_state.user = u
                st.rerun()
    with t2:
        nu = st.text_input("New Username")
        np = st.text_input("New Password", type="password")
        if st.button("Create Account"):
            try:
                conn.table("users").insert({"username": nu, "password": hashlib.sha256(np.encode()).hexdigest(), "op_count": 0}).execute()
                st.success("Success! Please Login.")
            except: st.error("Error creating account.")
else:
    # --- SIDEBAR ---
    with st.sidebar:
        st.header(f"Welcome, {st.session_state.user}")
        ops = get_usage(st.session_state.user)
        st.progress(min(ops / FREE_LIMIT, 1.0))
        st.write(f"Capacity: {ops} / {FREE_LIMIT}")
        
        menu = ["📜 About", "AES Symmetric", "RSA Asymmetric", "Diffie-Hellman", "Steganography", "Hashing"]
        if st.session_state.user == ADMIN_USERNAME: menu.insert(0, "👑 ADMIN")
        mode = st.selectbox("Menu", menu)
        
        if st.button("Logout"):
            st.session_state.logged_in = False
            st.rerun()

    # --- ABOUT PAGE ---
    if mode == "📜 About":
        st.header("About Vanguard Vault")
        st.markdown(f"""
        ### Multi-Layer Security Suite
        Developed by **ADELL Tech**, this vault provides industry-grade encryption.
        - **AES-256:** Your primary tool for locking and unlocking files or text with a password.
        - **RSA:** Advanced key-pair security.
        - **QR Support:** Instant QR generation for keys and hashes.
        - **Usage:** You get **{FREE_LIMIT} free operations**. Top up for ₦200 via the support link.
        """)

    # --- ADMIN PAGE ---
    elif mode == "👑 ADMIN":
        st.header("Admin Management")
        res = conn.table("users").select("*").execute()
        df = pd.DataFrame(res.data)
        st.dataframe(df)
        target = st.selectbox("User to Renew", df['username'].tolist())
        if st.button("Reset Operations to 0"):
            conn.table("users").update({"op_count": 0}).eq("username", target).execute()
            st.success("User Renewed!")

    # --- AES MODE ---
    elif mode == "AES Symmetric":
        st.header("AES Encryption & Decryption")
        pwd = st.text_input("Master Password", type="password")
        if pwd:
            key = base64.urlsafe_b64encode(hashlib.sha256(pwd.encode()).digest())
            tab1, tab2 = st.tabs(["Text", "Files"])
            with tab1:
                t_in = st.text_area("Input Text")
                col1, col2 = st.columns(2)
                if col1.button("Encrypt Text") and check_usage_limit():
                    st.code(Fernet(key).encrypt(t_in.encode()).decode())
                    increment_usage("AES-ENC")
                if col2.button("Decrypt Text") and check_usage_limit():
                    try:
                        st.success(Fernet(key).decrypt(t_in.encode()).decode())
                        increment_usage("AES-DEC")
                    except: st.error("Invalid Key")
            with tab2:
                up = st.file_uploader("File")
                if up:
                    data = up.read()
                    if st.button("Lock File") and check_usage_limit():
                        st.download_button("Download Locked", Fernet(key).encrypt(data), f"{up.name}.vault")
                        increment_usage("AES-FILE")
                    if st.button("Unlock File") and check_usage_limit():
                        try:
                            st.download_button("Download Unlocked", Fernet(key).decrypt(data), up.name)
                            increment_usage("AES-DECRYPT")
                        except: st.error("Wrong Password")

    # --- RSA MODE ---
    elif mode == "RSA Asymmetric":
        st.header("RSA Protocols")
        
        t1, t2 = st.tabs(["Keypair", "Execute"])
        with t1:
            if st.button("Generate RSA Keys") and check_usage_limit():
                priv = rsa.generate_private_key(65537, 2048)
                st.session_state.pub = priv.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
                st.session_state.priv = priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
                increment_usage("RSA-KEY")
            if 'pub' in st.session_state:
                st.code(st.session_state.pub)
                st.image(generate_qr(st.session_state.pub), caption="Scan Public Key")
        with t2:
            key_f = st.file_uploader("Key (.pem)")
            target = st.file_uploader("Target File")
            action = st.radio("Mode", ["Encrypt", "Decrypt"])
            if key_f and target and st.button("Run RSA"):
                if check_usage_limit():
                    if action == "Encrypt":
                        # RSA Encryption Logic
                        increment_usage("RSA-E")
                    else:
                        # RSA Decryption Logic
                        increment_usage("RSA-D")

    # --- OTHER MODES ---
    elif mode == "Steganography":
        st.header("Image Stealth")
        img_f = st.file_uploader("Image")
        msg = st.text_input("Secret")
        if img_f and msg and st.button("Hide"):
            if check_usage_limit():
                res = encode_image(Image.open(img_f).convert('RGB'), msg)
                buf = io.BytesIO(); res.save(buf, format="PNG")
                st.image(res); st.download_button("Download", buf.getvalue(), "secret.png")
                increment_usage("STEGO")

    elif mode == "Hashing":
        st.header("Integrity Hash")import streamlit as st
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

# --- SETUP & DATABASE CONNECTION ---
st.set_page_config(page_title="Vanguard Vault | ADELL Tech", layout="wide", page_icon="🛡️")

# Attempt to load your custom style module
try:
    from style import apply_custom_theme, show_status
    apply_custom_theme()
except:
    st.markdown("<style>.stButton>button {background-color: #00f2ff; color: black;}</style>", unsafe_allow_html=True)

# Secure Connection
try:
    st_url = st.secrets["connections"]["supabase"]["url"]
    st_key = st.secrets["connections"]["supabase"]["key"]
    conn = st.connection("supabase", type=SupabaseConnection, url=st_url, key=st_key)
except Exception as e:
    st.error("Database connection failed. Check your Streamlit Secrets.")
    st.stop()

# --- CONFIGURATION ---
FREE_LIMIT = 5 
ADMIN_USERNAME = "ADELL_ADMIN" 

# --- EDIT THESE DETAILS ---
BANK_NAME = "Your Bank Name"
ACCOUNT_NO = "0123456789"
ACCOUNT_NAME = "ADELL TECH"
WHATSAPP_NUMBER = "234XXXXXXXXXX" # e.g., 2348123456789

# --- UTILITY FUNCTIONS ---
def get_usage(username):
    try:
        res = conn.table("users").select("op_count").eq("username", username).execute()
        return res.data[0].get('op_count', 0) if res.data else 0
    except: return 0

def check_usage_limit():
    if st.session_state.get('user') == ADMIN_USERNAME: return True 
    count = get_usage(st.session_state.get('user'))
    if count >= FREE_LIMIT:
        st.error(f"🚨 **CAPACITY FINISHED ({count}/{FREE_LIMIT})**")
        st.markdown(f"""
        <div style="background-color: #1e1e1e; padding: 20px; border-radius: 10px; border: 2px solid #ff4b4b;">
            <h3 style="color: #ff4b4b; margin-top: 0;">Access Denied</h3>
            <p>Please pay <b>₦200</b> to get 5 more operations:</p>
            <p style="font-family: monospace; background: #000; padding: 10px; border-left: 5px solid #00f2ff;">
                Bank: {BANK_NAME}<br>
                Acct: {ACCOUNT_NO}<br>
                Name: {ACCOUNT_NAME}
            </p>
            <a href="https://wa.me/{WHATSAPP_NUMBER}?text=Payment%20made%20for%20Vault%20User:%20{st.session_state.user}" 
               target="_blank" style="display: inline-block; padding: 10px; background-color: #25D366; color: white; text-decoration: none; border-radius: 5px; font-weight: bold;">
               ✅ Send Proof to Admin (WhatsApp)
            </a>
        </div>
        """, unsafe_allow_html=True)
        return False
    return True

def increment_usage(action_name):
    if st.session_state.get('user') == ADMIN_USERNAME: return
    current_user = st.session_state.get('user')
    new_count = get_usage(current_user) + 1
    conn.table("users").update({"op_count": new_count}).eq("username", current_user).execute()
    # History Tracking
    timestamp = datetime.now().strftime("%H:%M:%S")
    if 'vault_history' not in st.session_state: st.session_state.vault_history = []
    st.session_state.vault_history.insert(0, f"[{timestamp}] {action_name}: Done")

def generate_qr(data):
    # This generates a URL for the QR code image
    encoded_data = urllib.parse.quote(str(data))
    return f"https://api.qrserver.com/v1/create-qr-code/?size=250x250&data={encoded_data}"

# --- CRYPTO LOGIC ---
def encode_image(img, secret_data):
    encoded = img.copy()
    binary_secret = ''.join(format(ord(i), '08b') for i in secret_data) + '1111111111111110'
    data_index = 0
    pixels = encoded.load()
    for y in range(img.height):
        for x in range(img.width):
            r, g, b = pixels[x, y]
            if data_index < len(binary_secret): r = r & ~1 | int(binary_secret[data_index]); data_index += 1
            if data_index < len(binary_secret): g = g & ~1 | int(binary_secret[data_index]); data_index += 1
            if data_index < len(binary_secret): b = b & ~1 | int(binary_secret[data_index]); data_index += 1
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
        try:
            char = chr(int(byte, 2))
            if decoded_text[-2:] == 'ÿþ': break
            decoded_text += char
        except: break
    return decoded_text[:-2]

# --- APP FLOW ---
if 'logged_in' not in st.session_state: st.session_state.logged_in = False

if not st.session_state.logged_in:
    st.title("🛡️ VANGUARD VAULT")
    t1, t2 = st.tabs(["LOGIN", "REGISTER"])
    with t1:
        u = st.text_input("Username")
        p = st.text_input("Password", type="password")
        if st.button("Login"):
            hpw = hashlib.sha256(p.encode()).hexdigest()
            res = conn.table("users").select("*").eq("username", u).eq("password", hpw).execute()
            if len(res.data) > 0:
                st.session_state.logged_in = True
                st.session_state.user = u
                st.rerun()
    with t2:
        nu = st.text_input("New Username")
        np = st.text_input("New Password", type="password")
        if st.button("Create Account"):
            try:
                conn.table("users").insert({"username": nu, "password": hashlib.sha256(np.encode()).hexdigest(), "op_count": 0}).execute()
                st.success("Success! Please Login.")
            except: st.error("Error creating account.")
else:
    # --- SIDEBAR ---
    with st.sidebar:
        st.header(f"Welcome, {st.session_state.user}")
        ops = get_usage(st.session_state.user)
        st.progress(min(ops / FREE_LIMIT, 1.0))
        st.write(f"Capacity: {ops} / {FREE_LIMIT}")
        
        menu = ["📜 About", "AES Symmetric", "RSA Asymmetric", "Diffie-Hellman", "Steganography", "Hashing"]
        if st.session_state.user == ADMIN_USERNAME: menu.insert(0, "👑 ADMIN")
        mode = st.selectbox("Menu", menu)
        
        if st.button("Logout"):
            st.session_state.logged_in = False
            st.rerun()

    # --- ABOUT PAGE ---
    if mode == "📜 About":
        st.header("About Vanguard Vault")
        st.markdown(f"""
        ### Multi-Layer Security Suite
        Developed by **ADELL Tech**, this vault provides industry-grade encryption.
        - **AES-256:** Your primary tool for locking and unlocking files or text with a password.
        - **RSA:** Advanced key-pair security.
        - **QR Support:** Instant QR generation for keys and hashes.
        - **Usage:** You get **{FREE_LIMIT} free operations**. Top up for ₦200 via the support link.
        """)

    # --- ADMIN PAGE ---
    elif mode == "👑 ADMIN":
        st.header("Admin Management")
        res = conn.table("users").select("*").execute()
        df = pd.DataFrame(res.data)
        st.dataframe(df)
        target = st.selectbox("User to Renew", df['username'].tolist())
        if st.button("Reset Operations to 0"):
            conn.table("users").update({"op_count": 0}).eq("username", target).execute()
            st.success("User Renewed!")

    # --- AES MODE ---
    elif mode == "AES Symmetric":
        st.header("AES Encryption & Decryption")
        pwd = st.text_input("Master Password", type="password")
        if pwd:
            key = base64.urlsafe_b64encode(hashlib.sha256(pwd.encode()).digest())
            tab1, tab2 = st.tabs(["Text", "Files"])
            with tab1:
                t_in = st.text_area("Input Text")
                col1, col2 = st.columns(2)
                if col1.button("Encrypt Text") and check_usage_limit():
                    st.code(Fernet(key).encrypt(t_in.encode()).decode())
                    increment_usage("AES-ENC")
                if col2.button("Decrypt Text") and check_usage_limit():
                    try:
                        st.success(Fernet(key).decrypt(t_in.encode()).decode())
                        increment_usage("AES-DEC")
                    except: st.error("Invalid Key")
            with tab2:
                up = st.file_uploader("File")
                if up:
                    data = up.read()
                    if st.button("Lock File") and check_usage_limit():
                        st.download_button("Download Locked", Fernet(key).encrypt(data), f"{up.name}.vault")
                        increment_usage("AES-FILE")
                    if st.button("Unlock File") and check_usage_limit():
                        try:
                            st.download_button("Download Unlocked", Fernet(key).decrypt(data), up.name)
                            increment_usage("AES-DECRYPT")
                        except: st.error("Wrong Password")

    # --- RSA MODE ---
    elif mode == "RSA Asymmetric":
        st.header("RSA Protocols")
        
        t1, t2 = st.tabs(["Keypair", "Execute"])
        with t1:
            if st.button("Generate RSA Keys") and check_usage_limit():
                priv = rsa.generate_private_key(65537, 2048)
                st.session_state.pub = priv.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
                st.session_state.priv = priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
                increment_usage("RSA-KEY")
            if 'pub' in st.session_state:
                st.code(st.session_state.pub)
                st.image(generate_qr(st.session_state.pub), caption="Scan Public Key")
        with t2:
            key_f = st.file_uploader("Key (.pem)")
            target = st.file_uploader("Target File")
            action = st.radio("Mode", ["Encrypt", "Decrypt"])
            if key_f and target and st.button("Run RSA"):
                if check_usage_limit():
                    if action == "Encrypt":
                        # RSA Encryption Logic
                        increment_usage("RSA-E")
                    else:
                        # RSA Decryption Logic
                        increment_usage("RSA-D")

    # --- OTHER MODES ---
    elif mode == "Steganography":
        st.header("Image Stealth")
        img_f = st.file_uploader("Image")
        msg = st.text_input("Secret")
        if img_f and msg and st.button("Hide"):
            if check_usage_limit():
                res = encode_image(Image.open(img_f).convert('RGB'), msg)
                buf = io.BytesIO(); res.save(buf, format="PNG")
                st.image(res); st.download_button("Download", buf.getvalue(), "secret.png")
                increment_usage("STEGO")

    elif mode == "Hashing":
        st.header("Integrity Hash")
        h_f = st.file_uploader("File to Hash")
        if h_f and st.button("Generate SHA-256"):
            if check_usage_limit():
                res = hashlib.sha256(h_f.read()).hexdigest()
                st.code(res)
                st.image(generate_qr(res))
                increment_usage("HASH")
        h_f = st.file_uploader("File to Hash")
        if h_f and st.button("Generate SHA-256"):
            if check_usage_limit():
                res = hashlib.sha256(h_f.read()).hexdigest()
                st.code(res)
                st.image(generate_qr(res))
                increment_usage("HASH")