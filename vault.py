import streamlit as st
from st_supabase_connection import SupabaseConnection
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import base64
import hashlib
import io
import pandas as pd
from datetime import datetime
import urllib.parse
from PIL import Image

# --- IMPORT YOUR CUSTOM STYLING ---
from style import apply_custom_theme, show_status

# --- INITIAL SETUP ---
st.set_page_config(page_title="Vanguard Vault | ADELL Tech", layout="wide", page_icon="🛡️")
apply_custom_theme()

# --- DATABASE CONNECTION (REPAIRED) ---
from supabase import create_client, Client

# These names must match EXACTLY what is in your Streamlit Secrets
try:
    url = st.secrets["connections"]["supabase"]["url"]
    key = st.secrets["connections"]["supabase"]["key"]
    conn = create_client(url, key)
except Exception as e:
    st.error(f"Connection Failed. Error: {e}")
    st.info("Check your Secrets: You need [connections.supabase] with 'url' and 'key'")
    st.stop()

# --- CONFIGURATION ---
FREE_LIMIT = 5
ADMIN_USERNAME = "ADELL_ADMIN"
WHATSAPP_NUMBER = "2347059194126" 
BANK_INFO = "BANK: Opay | ACCT: 7059194126 | NAME: ADELL TECH"

# --- SYSTEM UTILITIES ---
def get_usage(username):
    try:
        res = conn.table("users").select("op_count").eq("username", username).execute()
        return res.data[0]['op_count'] if res.data else 0
    except: return 0

def check_usage_limit():
    if st.session_state.get('user') == ADMIN_USERNAME: return True
    count = get_usage(st.session_state.get('user'))
    if count >= FREE_LIMIT:
        st.markdown(f"""
            <div style="background: #1a0000; padding: 20px; border: 2px solid #ff4b4b; border-radius: 8px; margin-bottom: 20px;">
                <h3 style="color: #ff4b4b !important; margin-top:0;">🚨 CAPACITY EXHAUSTED</h3>
                <p>You have reached your {FREE_LIMIT}-operation limit.</p>
                <p>To continue, pay <b>₦200</b> to:</p>
                <code style="color: #00f2ff; display:block; background:#000; padding:10px; border-radius:4px;">{BANK_INFO}</code><br>
                <a href="https://wa.me/{WHATSAPP_NUMBER}?text=Payment%20Proof%20for%20Vault%20User:%20{st.session_state.user}" target="_blank">
                    <button style="background:#25D366; color:white; border:none; padding:12px; width:100%; border-radius:5px; font-weight:bold; cursor:pointer;">
                        SEND PROOF ON WHATSAPP
                    </button>
                </a>
            </div>
        """, unsafe_allow_html=True)
        return False
    return True

def increment_usage(action):
    if st.session_state.get('user') == ADMIN_USERNAME: return
    new_count = get_usage(st.session_state.user) + 1
    conn.table("users").update({"op_count": new_count}).eq("username", st.session_state.user).execute()
    if 'history' not in st.session_state: st.session_state.history = []
    st.session_state.history.insert(0, f"{datetime.now().strftime('%H:%M')} - {action}")

# --- CRYPTO ENGINES ---
def encode_stego(img, data):
    encoded = img.copy()
    binary_data = ''.join(format(ord(i), '08b') for i in data) + '1111111111111110'
    idx, pix = 0, encoded.load()
    for y in range(img.height):
        for x in range(img.width):
            r, g, b = pix[x, y]
            if idx < len(binary_data): r = r & ~1 | int(binary_data[idx]); idx += 1
            if idx < len(binary_data): g = g & ~1 | int(binary_data[idx]); idx += 1
            if idx < len(binary_data): b = b & ~1 | int(binary_data[idx]); idx += 1
            pix[x, y] = (r, g, b)
            if idx >= len(binary_data): return encoded
    return encoded

def decode_stego(img):
    bin_str = ""
    pix = img.load()
    for y in range(img.height):
        for x in range(img.width):
            r, g, b = pix[x, y]
            bin_str += f"{r&1}{g&1}{b&1}"
    chars = [chr(int(bin_str[i:i+8], 2)) for i in range(0, len(bin_str), 8)]
    return "".join(chars).split('ÿþ')[0]

# --- USER INTERFACE FLOW ---
if 'user' not in st.session_state:
    st.title("🛡️ VANGUARD VAULT")
    t1, t2 = st.tabs(["Login", "Register"])
    with t1:
        u = st.text_input("Username")
        p = st.text_input("Password", type="password")
        if st.button("Access Vault"):
            hp = hashlib.sha256(p.encode()).hexdigest()
            res = conn.table("users").select("*").eq("username", u).eq("password", hp).execute()
            if res.data:
                st.session_state.user = u
                st.rerun()
            else: st.error("Access Denied: Invalid Credentials")
    with t2:
        nu = st.text_input("New Identity")
        np = st.text_input("New Passkey", type="password")
        if st.button("Create Account"):
            try:
                conn.table("users").insert({"username": nu, "password": hashlib.sha256(np.encode()).hexdigest(), "op_count": 0}).execute()
                st.success("Identity Verified. Proceed to Login.")
            except: st.error("Identity already exists in database.")

else:
    # --- SIDEBAR (CONSOLIDATED USER TERMINAL) ---
    with st.sidebar:
        st.markdown(f"### OPERATOR: {st.session_state.user}")
        show_status() 
        
        # 1. Fetch Fresh User Data
        userData = conn.table("users").select("*").eq("username", st.session_state.user).execute().data[0]
        used = userData['op_count']
        refills = userData['payment_count']
        
        # 2. Display Credits & Refill History
        st.progress(min(used/5, 1.0))
        st.caption(f"Credits Remaining: {5 - used} / 5")
        
        st.markdown(f"""
            <div style="background: #001515; padding: 10px; border-radius: 5px; border: 1px solid #00f2ff; margin-bottom: 10px;">
                <p style="margin:0; font-size: 0.8rem; color: #00f2ff;">Total Refills Purchased: <b>{refills}</b></p>
                <p style="margin:0; font-size: 0.7rem; color: #888;">Thank you for supporting ADELL Tech</p>
            </div>
        """, unsafe_allow_html=True)

        # --- RECEIPT GENERATOR ---
        if refills > 0:
            receipt_content = f"""
            ====================================
            VANGUARD VAULT OFFICIAL RECEIPT
            ====================================
            Operator: {st.session_state.user}
            Status: VERIFIED USER
            Total Refills: {refills}
            Total Investment: ₦{refills * 200}
            Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}
            ====================================
            SECURED BY ADELL TECH PROTOCOLS
            ====================================
            """
            st.download_button(
                label="📄 DOWNLOAD PAYMENT PROOF",
                data=receipt_content,
                file_name=f"Vault_Receipt_{st.session_state.user}.txt",
                mime="text/plain"
            )
        
        st.markdown("---")
        
        # 3. Terminal Logs
        st.markdown("📜 **TERMINAL LOGS**")
        if 'history' in st.session_state:
            for log in st.session_state.history[:3]:
                st.markdown(f"<p style='font-family:monospace; font-size:0.7rem; color:#80ced6; margin:0;'>{log}</p>", unsafe_allow_html=True)
        
        st.markdown("---")

        # 4. Navigation Menu
        menu = ["AES Symmetric", "RSA Asymmetric", "Steganography", "Hashing", "ℹ️ About"]
        if st.session_state.user == ADMIN_USERNAME:
            menu.insert(0, "👑 ADMIN")
        
        mode = st.selectbox("Select Module", menu)
        
        # 5. Session Control
        if st.button("Terminate Session"):
            del st.session_state.user
            st.rerun()

    # --- AES MODULE ---
    if mode == "AES Symmetric":
        st.header("AES-256 Symmetric Locker")
        master_key = st.text_input("Master Password", type="password")
        if master_key:
            k = base64.urlsafe_b64encode(hashlib.sha256(master_key.encode()).digest())
            f = Fernet(k)
            t_text, t_file = st.tabs(["TEXT LOCK", "FILE LOCK"])
            
            with t_text:
                col_e, col_d = st.columns(2)
                with col_e:
                    txt = st.text_area("Plaintext")
                    if st.button("Encrypt Text") and check_usage_limit():
                        st.code(f.encrypt(txt.encode()).decode())
                        increment_usage("AES_TXT_ENC")
                with col_d:
                    ctxt = st.text_area("Ciphertext")
                    if st.button("Decrypt Text") and check_usage_limit():
                        try:
                            st.success(f.decrypt(ctxt.encode()).decode())
                            increment_usage("AES_TXT_DEC")
                        except: st.error("Invalid Key")

            with t_file:
                up_f = st.file_uploader("Upload File")
                if up_f and st.button("Protect File") and check_usage_limit():
                    enc_data = f.encrypt(up_f.read())
                    st.download_button("Download .vault", enc_data, f"{up_f.name}.vault")
                    increment_usage("AES_FILE_ENC")

    # --- RSA MODULE ---
    elif mode == "RSA Asymmetric":
        st.header("RSA Asymmetric Suite")
        t_keygen, t_encrypt, t_decrypt = st.tabs(["🔑 KEYGEN", "🔒 ENCRYPT", "🔓 DECRYPT"])
        
        with t_keygen:
            st.info("RSA keys come in pairs. Share your **Public Key** to receive secrets. Keep your **Private Key** hidden.")
            if st.button("Generate 2048-bit RSA Pair") and check_usage_limit():
                private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
                public_key = private_key.public_key()
                
                pem_private = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ).decode()
                
                pem_public = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode()
                
                st.session_state.temp_private = pem_private
                st.session_state.temp_public = pem_public
                increment_usage("RSA_KEYGEN")
            
            if 'temp_public' in st.session_state:
                st.subheader("📤 Your Public Key")
                st.caption("Hover over the box below and click the icon to copy.")
                st.code(st.session_state.temp_public, language="text")
                
                st.subheader("🗝️ Your Private Key")
                st.warning("NEVER share this key. If lost, encrypted data is unrecoverable.")
                st.code(st.session_state.temp_private, language="text")
                
                qr_url = f"https://api.qrserver.com/v1/create-qr-code/?size=180x180&data={urllib.parse.quote(st.session_state.temp_public)}"
                st.image(qr_url, caption="Public Key QR (Scan to copy)")

        with t_encrypt:
            st.subheader("Encrypt for a Recipient")
            pub_input = st.text_area("Paste the Receiver's Public Key here")
            secret_msg = st.text_input("Message to lock")
            
            if st.button("🔒 Secure Message") and check_usage_limit():
                try:
                    recipient_key = serialization.load_pem_public_key(pub_input.encode())
                    ciphertext = recipient_key.encrypt(
                        secret_msg.encode(),
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    st.success("Message Locked. Copy the ciphertext below and send it.")
                    st.code(base64.b64encode(ciphertext).decode(), language="text")
                    increment_usage("RSA_ENC")
                except Exception as e:
                    st.error("Invalid Public Key. Please ensure you copied the full key including 'BEGIN PUBLIC KEY'.")

        with t_decrypt:
            st.subheader("Unlock a Message Sent to You")
            priv_input = st.text_area("Paste YOUR Private Key here")
            cipher_input = st.text_area("Paste the Encrypted Ciphertext here")
            
            if st.button("🔓 Open Vault"):
                if check_usage_limit():
                    try:
                        my_private_key = serialization.load_pem_private_key(priv_input.encode(), password=None)
                        raw_cipher = base64.b64decode(cipher_input.strip().encode())
                        plaintext = my_private_key.decrypt(
                            raw_cipher,
                            padding.OAEP(
                                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                algorithm=hashes.SHA256(),
                                label=None
                            )
                        )
                        st.balloons()
                        st.success(f"Decrypted Content: {plaintext.decode()}")
                        increment_usage("RSA_DEC")
                    except Exception as e:
                        st.error("Decryption failed. This message was likely encrypted for a different key pair.")

    # --- STEGANOGRAPHY MODULE ---
    elif mode == "Steganography":
        st.header("Steganography Engine")
        s_h, s_r = st.tabs(["HIDE", "REVEAL"])
        with s_h:
            img = st.file_uploader("Cover Image", type=['png', 'jpg'])
            msg = st.text_input("Secret Message")
            if img and msg and st.button("Embed"):
                if check_usage_limit():
                    res = encode_stego(Image.open(img).convert('RGB'), msg)
                    buf = io.BytesIO()
                    res.save(buf, format="PNG")
                    st.image(res)
                    st.download_button("Download", buf.getvalue(), "vault.png")
                    increment_usage("STEGO_HIDE")
        with s_r:
            img_s = st.file_uploader("Stego Image", type=['png'])
            if img_s and st.button("Extract"):
                if check_usage_limit():
                    st.info(f"Secret: {decode_stego(Image.open(img_s).convert('RGB'))}")
                    increment_usage("STEGO_REVEAL")

    # --- HASHING MODULE ---
    elif mode == "Hashing":
        st.header("Integrity Hashing (SHA-256)")
        h_file = st.file_uploader("File to Hash")
        if h_file and st.button("Generate Fingerprint"):
            if check_usage_limit():
                res_h = hashlib.sha256(h_file.read()).hexdigest()
                st.code(res_h)
                qr_h = f"https://api.qrserver.com/v1/create-qr-code/?size=150x150&data={res_h}"
                st.image(qr_h)
                increment_usage("HASH_GEN")

    # --- ABOUT MODULE ---
    elif mode == "ℹ️ About":
        st.header("VANGUARD VAULT SYSTEM")
        st.markdown("""
        ### Developed by ADELL Tech
        **Version:** 2.0 (Stable)  
        **Protocols:** AES-256, RSA-2048, LSB Steganography.
        
        This system is designed for secure communication and storage. For support or custom development, 
        contact us via the button in the sidebar or via WhatsApp.
        """)
        
    # --- ADMIN MODULE ---
    elif mode == "👑 ADMIN":
        st.header("Admin Command Center")
        try:
            response = conn.table("users").select("*").execute()
            df = pd.DataFrame(response.data)
            
            if not df.empty:
                # Calculate Revenue: Each payment count * 200
                total_revenue = df['payment_count'].sum() * 200
                
                col_m1, col_m2, col_m3 = st.columns(3)
                col_m1.metric("Total Operators", len(df))
                col_m2.metric("Total Refills Sold", int(df['payment_count'].sum()))
                col_m3.metric("Total Earnings", f"₦{total_revenue:,}")
                
                st.markdown("---")
                st.subheader("User Payment History")
                # Show username, current usage, and how many times they've paid
                st.dataframe(df[['username', 'op_count', 'payment_count']], use_container_width=True)
                
                st.markdown("---")
                target_user = st.selectbox("Select User to Refill", df['username'].tolist())
                
                if st.button("💰 VERIFY ₦200 & GRANT +5 OPS"):
                    # Get current payment count
                    current_p = df[df['username'] == target_user]['payment_count'].values[0]
                    # Reset usage to 0 and increase payment count by 1
                    conn.table("users").update({
                        "op_count": 0, 
                        "payment_count": int(current_p + 1)
                    }).eq("username", target_user).execute()
                    
                    st.success(f"Refill Successful! {target_user} now has 5 new credits.")
                    st.balloons()
                    st.rerun()
            else:
                st.warning("No identities found.")
        except Exception as e:
            st.error(f"Sync error: {e}")