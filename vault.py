import streamlit as st
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import base64
import hashlib
import io
import pandas as pd
from datetime import datetime
from PIL import Image
from supabase import create_client, Client

# --- IMPORT YOUR CUSTOM STYLING ---
try:
    from style import apply_custom_theme, show_status
except ImportError:
    def apply_custom_theme(): pass
    def show_status(): st.sidebar.success("System Online")

# --- INITIAL SETUP ---
st.set_page_config(page_title="Vanguard Vault | ADELL Tech", layout="wide", page_icon="🛡️")
apply_custom_theme()

# --- DATABASE CONNECTION ---
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

# --- STEGO UTILS ---
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

# --- UI LOGIC ---
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
            else: st.error("Access Denied")
    with t2:
        nu = st.text_input("New Identity")
        np = st.text_input("New Passkey", type="password")
        
        with st.expander("📄 View Terms of Service"):
            st.caption("1. ADELL Tech cannot recover forgotten file passwords.")
            st.caption("2. Credits (₦200/5 ops) are non-refundable.")
            st.caption("3. You are responsible for your own RSA Private Keys.")
        
        agree = st.checkbox("I accept the ADELL Tech Terms of Service")
        
        if st.button("Create Account"):
            if not agree:
                st.warning("You must accept the terms to proceed.")
            else:
                try:
                    conn.table("users").insert({"username": nu, "password": hashlib.sha256(np.encode()).hexdigest(), "op_count": 0, "payment_count": 0}).execute()
                    st.success("Identity Verified. Proceed to Login.")
                except: st.error("Identity already exists.")
else:
    # --- SIDEBAR ---
    with st.sidebar:
        st.markdown(f"### OPERATOR: {st.session_state.user}")
        show_status() 
        userData = conn.table("users").select("*").eq("username", st.session_state.user).execute().data[0]
        used, refills = userData['op_count'], userData.get('payment_count', 0)
        
        st.progress(min(used/5, 1.0))
        st.caption(f"Credits Remaining: {5 - used} / 5")
        
        if refills > 0:
            receipt = f"VANGUARD VAULT RECEIPT\nOperator: {st.session_state.user}\nRefills: {refills}\nDate: {datetime.now().strftime('%Y-%m-%d')}"
            st.download_button("📄 DOWNLOAD RECEIPT", receipt, f"Receipt_{st.session_state.user}.txt")
        
        menu = ["AES Symmetric", "RSA Asymmetric", "Steganography", "Hashing", "Diffie-Hellman", "ℹ️ About"]
        if st.session_state.user == ADMIN_USERNAME: menu.insert(0, "👑 ADMIN")
        mode = st.selectbox("Select Module", menu)

        with st.expander("👤 Security Settings"):
            old_p = st.text_input("Current Passkey", type="password")
            up_p = st.text_input("New Passkey", type="password")
            if st.button("Update Passkey"):
                if hashlib.sha256(old_p.encode()).hexdigest() == userData['password']:
                    conn.table("users").update({"password": hashlib.sha256(up_p.encode()).hexdigest()}).eq("username", st.session_state.user).execute()
                    st.success("Passkey Updated!")
                else: st.error("Incorrect Current Passkey")
        
        if st.button("Terminate Session"):
            del st.session_state.user
            st.rerun()

    # --- AES ---
    if mode == "AES Symmetric":
        st.header("AES-256 Symmetric Locker")
        master_key = st.text_input("Master Password", type="password")
        if master_key:
            k = base64.urlsafe_b64encode(hashlib.sha256(master_key.encode()).digest())
            f = Fernet(k)
            t_txt, t_file = st.tabs(["📝 TEXT", "🎬 FILE/VIDEO"])
            with t_txt:
                col1, col2 = st.columns(2)
                with col1:
                    txt = st.text_area("Plaintext")
                    if st.button("Encrypt Text") and check_usage_limit():
                        st.code(f.encrypt(txt.encode()).decode())
                        increment_usage("AES_ENC")
                with col2:
                    ctxt = st.text_area("Ciphertext")
                    if st.button("Decrypt Text") and check_usage_limit():
                        try: st.success(f.decrypt(ctxt.encode()).decode())
                        except: st.error("Invalid Key")
            with t_file:
                up = st.file_uploader("Upload File")
                if up and st.button("🔒 Encrypt") and check_usage_limit():
                    st.download_button(f"Download {up.name}.aes", f.encrypt(up.read()), f"{up.name}.aes")
                    increment_usage("AES_FILE")

    # --- RSA MODULE (HYBRID + TEXT) ---
    elif mode == "RSA Asymmetric":
        st.header("RSA Asymmetric Suite")
        tk, te, td = st.tabs(["🔑 KEYGEN", "🔒 ENCRYPT (Text & Files)", "🔓 DECRYPT"])
        
        with tk:
            if st.button("Generate RSA Pair") and check_usage_limit():
                private_key = rsa.generate_private_key(65537, 2048)
                pem_p = private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
                pem_pub = private_key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
                st.code(pem_pub, label="Public Key (Share This)"); st.code(pem_p, label="Private Key (KEEP SECRET)")
                increment_usage("RSA_KEYGEN")

        with te:
            st.subheader("Encryption")
            pub_in = st.text_area("Recipient Public Key")
            m_type = st.radio("What are you locking?", ["Short Message", "Large File/Video"])
            
            if m_type == "Short Message":
                msg_in = st.text_input("Message")
                if st.button("Encrypt Message") and check_usage_limit():
                    try:
                        pub = serialization.load_pem_public_key(pub_in.encode())
                        cipher = pub.encrypt(msg_in.encode(), padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None))
                        st.code(base64.b64encode(cipher).decode())
                        increment_usage("RSA_MSG")
                    except: st.error("Check Public Key")
            else:
                up_f = st.file_uploader("Upload File")
                if up_f and pub_in and st.button("RSA-Lock File") and check_usage_limit():
                    # HYBRID: AES for file, RSA for Key
                    s_key = Fernet.generate_key()
                    f_aes = Fernet(s_key)
                    enc_file = f_aes.encrypt(up_f.read())
                    pub = serialization.load_pem_public_key(pub_in.encode())
                    enc_s_key = pub.encrypt(s_key, padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None))
                    
                    st.success("File Ready!")
                    st.code(base64.b64encode(enc_s_key).decode(), label="Recipient's Unlock Key (Send this via Text)")
                    st.download_button("Download Encrypted File", enc_file, f"{up_f.name}.vault")
                    increment_usage("RSA_FILE")

        with td:
            priv_in = st.text_area("Your Private Key")
            cip_in = st.text_area("Encrypted Key or Message")
            if st.button("Decrypt"):
                try:
                    priv = serialization.load_pem_private_key(priv_in.encode(), None)
                    res = priv.decrypt(base64.b64decode(cip_in.encode()), padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None))
                    st.success(f"Decrypted: {res.decode()}")
                except: st.error("Decryption Failed")

    # --- DIFFIE-HELLMAN MODULE ---
    elif mode == "Diffie-Hellman":
        st.header("Diffie-Hellman Key Exchange")
        st.info("Establish a secret key with someone else without ever sending the key itself.")
        from cryptography.hazmat.primitives.asymmetric import dh
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF

        # Standard DH Parameters (Group 14)
        pn = dh.generate_parameters(generator=2, key_size=2048)
        
        c1, c2 = st.columns(2)
        with c1:
            if st.button("1. Generate My DH Private/Public"):
                priv = pn.generate_private_key()
                pub = priv.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
                st.session_state.dh_priv = priv
                st.code(pub, label="Send this Public Part to Partner")
        
        with c2:
            partner_pub_pem = st.text_area("2. Paste Partner's Public Part")
            if st.button("3. Compute Shared Secret") and 'dh_priv' in st.session_state:
                try:
                    p_pub = serialization.load_pem_public_key(partner_pub_pem.encode())
                    shared = st.session_state.dh_priv.exchange(p_pub)
                    # Derive a usable 32-byte key
                    derived = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'dh-exchange').derive(shared)
                    st.success("Shared Secret Established!")
                    st.code(base64.urlsafe_b64encode(derived).decode(), label="Use this in AES Module")
                    increment_usage("DH_EXCHANGE")
                except: st.error("Invalid Partner Key")

    # --- STEGANOGRAPHY ---
    elif mode == "Steganography":
        st.header("Steganography Engine")
        sh, sr = st.tabs(["HIDE", "REVEAL"])
        with sh:
            img = st.file_uploader("Cover Image", type=['png', 'jpg'])
            msg = st.text_input("Secret")
            if img and msg and st.button("Embed") and check_usage_limit():
                res = encode_stego(Image.open(img).convert('RGB'), msg)
                buf = io.BytesIO(); res.save(buf, "PNG")
                st.image(res); st.download_button("Download Image", buf.getvalue(), "vault.png")
        with sr:
            img_s = st.file_uploader("Stego Image", type=['png'])
            if img_s and st.button("Extract"):
                st.info(f"Secret: {decode_stego(Image.open(img_s).convert('RGB'))}")

    # --- HASHING ---
    elif mode == "Hashing":
        st.header("Integrity Hashing")
        hf = st.file_uploader("Fingerprint File")
        if hf and st.button("Generate Hash") and check_usage_limit():
            st.code(hashlib.sha256(hf.read()).hexdigest())

    # --- ABOUT ---
    elif mode == "ℹ️ About":
        st.header("🛡️ VANGUARD VAULT | SYSTEM OVERVIEW")
        col1, col2 = st.columns([2, 1])
        with col1:
            st.markdown("""
### **1. Getting Started**
* **Identity Creation:** Your username is your unique ID. Your Passkey is the master lock for your data. **Warning:** If you lose your passkey, ADELL Tech can reset your account access, but encrypted data may be lost forever.
* **Credits:** Every account starts with **5 Free Operations**.

### **2. AES Symmetric Locker**
* **How it works:** Uses a single password to lock and unlock data.
* **Locking:** Upload a file, enter your password, and click **🔒 Encrypt**.
* **Unlocking:** Upload the .aes file, enter the same password, and click **🔓 Decrypt**.

### **3. RSA Asymmetric Suite**
* **The Pair:** You generate a **Public Key** (share this) and a **Private Key** (keep secret).
* **Sending:** Use the recipient's Public Key to encrypt. Only their Private Key can open it.

### **4. Steganography**
* **Hide:** Upload an image and type your secret. The system embeds text into pixels.
* **Note:** Use "Document" mode when sending via WhatsApp to avoid data loss.

### **5. Capacity & Refills**
When credits are exhausted, pay **₦200** to the bank info provided and send proof via WhatsApp to refill.
            """)
        with col2:
            st.info("**Developer:** ADELL Tech  \n**Version:** 2.0  \n**Security:** High  \n**Database:** Supabase")
        st.markdown("---")
        st.write(f"Refills or Technical Issues: WhatsApp {WHATSAPP_NUMBER}")

    # --- ADMIN ---
    elif mode == "👑 ADMIN":
        st.header("Admin Command Center")
        df = pd.DataFrame(conn.table("users").select("*").execute().data)
        if not df.empty:
            st.metric("Total Revenue", f"₦{df['payment_count'].sum() * 200}")
            st.dataframe(df[['username', 'op_count', 'payment_count']])
            
            target = st.selectbox("Select User for Action", df['username'].tolist())
            c_refill, c_reset = st.columns(2)
            with c_refill:
                if st.button("Verify & Refill"):
                    curr_p = df[df['username'] == target]['payment_count'].values[0]
                    conn.table("users").update({"op_count": 0, "payment_count": int(curr_p + 1)}).eq("username", target).execute()
                    st.success("Refilled!"); st.rerun()
            with c_reset:
                new_p = st.text_input("Temp Passkey", value="VAULT123")
                if st.button("Reset Passkey"):
                    conn.table("users").update({"password": hashlib.sha256(new_p.encode()).hexdigest()}).eq("username", target).execute()
                    st.warning(f"Reset to {new_p}")