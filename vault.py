import streamlit as st
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import base64
import hashlib
import io
import pandas as pd
from datetime import datetime
from PIL import Image
from supabase import create_client, Client
import stepic

# --- CUSTOM STYLING MODULE ---
st.markdown("---")
try:
    # We import them directly at the top level
    from style import apply_custom_theme, show_status
except ImportError:
    # If style.py is missing, we define "empty" fallbacks so the app doesn't break
    def apply_custom_theme(): pass 
    def show_status(): st.sidebar.warning("⚠️ Style System Offline")

# --- INITIAL SETUP ---
st.set_page_config(page_title="Vanguard Vault | ADELL Tech", layout="wide", page_icon="🛡️")

# Now we call the function we imported
apply_custom_theme()

# --- DATABASE CONNECTION ---
try:
    url = st.secrets["connections"]["supabase"]["url"]
    key = st.secrets["connections"]["supabase"]["key"]
    conn = create_client(url, key)
except Exception as e:
    st.error("Database Connection Offline.")
    st.stop()

# --- CONFIGURATION ---
FREE_LIMIT = 5
ADMIN_USERNAME = "ADELL_ADMIN"
WHATSAPP_NUMBER = "2347059194126" 
BANK_INFO = "BANK: Opay | ACCT: 7059194126 | NAME: ADELL TECH"
if FLUTTERWAVE_LINK == "#":
    st.button("💳 GATEWAY COMING SOON", disabled=True)
else:
    st.markdown(f'<a href="{FLUTTERWAVE_LINK}" target="_blank"><button style="...">PAY VIA GATEWAY</button></a>', unsafe_allow_html=True)

# --- SYSTEM UTILITIES ---
def add_log(username, action):
    try:
        conn.table("logs").insert({"username": username, "action": action}).execute()
    except: pass

def get_usage(username):
    try:
        res = conn.table("users").select("op_count").eq("username", username).execute()
        return res.data[0]['op_count'] if res.data else 0
    except: return 0

def check_usage_limit():
    if st.session_state.get('user') == ADMIN_USERNAME: return True
    count = get_usage(st.session_state.get('user'))
    
    if count >= FREE_LIMIT:
        # Determine if we should enable the Flutterwave button
        is_live = FLUTTERWAVE_LINK != "#" and FLUTTERWAVE_LINK is not None
        
        st.markdown(f"""
            <div style="background: #001215; padding: 20px; border: 2px solid #00f2ff; border-radius: 8px; margin-bottom: 20px;">
                <h3 style="color: #00f2ff !important; margin-top:0;">🛡️ VAULT RECHARGE REQUIRED</h3>
                <p style="color: #e0faff;">Your free operations are exhausted. Choose a payment method to get <b>5 more credits (₦200)</b>.</p>
                
                <div style="display: flex; gap: 10px; margin-bottom: 15px;">
                    <div style="flex: 1; border: 1px solid #fbba00; padding: 10px; border-radius: 5px; text-align: center;">
                        <p style="font-size: 0.8rem; color: #fbba00; font-weight: bold; margin-bottom: 8px;">WEB GATEWAY</p>
                        <a href="{FLUTTERWAVE_LINK if is_live else '#'}" target="_blank" style="text-decoration: none;">
                            <button class="flutterwave-btn" {"" if is_live else "disabled style='background:#444; color:#888; cursor:not-allowed;'"}>
                                { "PAY VIA CARD" if is_live else "GATEWAY SOON" }
                            </button>
                        </a>
                    </div>
                    
                    <div style="flex: 1; border: 1px solid #00f2ff; padding: 10px; border-radius: 5px; text-align: center;">
                        <p style="font-size: 0.8rem; color: #00f2ff; font-weight: bold; margin-bottom: 8px;">BANK TRANSFER</p>
                        <code style="font-size: 0.75rem; color: #00f2ff;">{BANK_INFO}</code>
                    </div>
                </div>

                <p style="font-size: 0.8rem; color: #80ced6; text-align: center; margin-bottom: 10px;">After payment, send proof for instant refill:</p>
                <a href="https://wa.me/{WHATSAPP_NUMBER}?text=Payment%20Proof%20for%20Vault%20User:%20{st.session_state.user}" target="_blank" style="text-decoration: none;">
                    <button style="background:#25D366; color:white; border:none; padding:12px; width:100%; border-radius:5px; font-weight:bold; cursor:pointer;">
                        ⚡ SEND PROOF ON WHATSAPP
                    </button>
                </a>
            </div>
        """, unsafe_allow_html=True)
        return False
    return True

def increment_usage(action_label):
    if st.session_state.get('user') == ADMIN_USERNAME: return
    # Get current usage and update
    current_count = get_usage(st.session_state.user)
    new_count = current_count + 1
    
    try:
        conn.table("users").update({"op_count": new_count}).eq("username", st.session_state.user).execute()
        add_log(st.session_state.user, action_label)
    except Exception as e:
        st.error(f"Sync Error: {e}")

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
                add_log(u, "SYSTEM_LOGIN")
                st.rerun()
            else: 
                st.error("Access Denied")
        
        st.markdown("---")
        # --- FORGOT PASSKEY SECTION ---
        with st.expander("🔑 Forgot Passkey?"):
            st.caption("Reset your passkey using your 12-character Recovery Code.")
            rec_u = st.text_input("Username", key="forgot_u")
            rec_code = st.text_input("Recovery Code")
            new_p = st.text_input("New Passkey", type="password")
            
            if st.button("Reset & Reclaim Account"):
                if rec_u and rec_code and new_p:
                    # Verify recovery code
                    res = conn.table("users").select("*").eq("username", rec_u).eq("recovery_code", rec_code).execute()
                    if res.data:
                        new_hp = hashlib.sha256(new_p.encode()).hexdigest()
                        conn.table("users").update({"password": new_hp}).eq("username", rec_u).execute()
                        st.success("Passkey Reset Successful! You can now login above.")
                        add_log(rec_u, "RECOVERY_SUCCESS")
                    else:
                        st.error("Invalid Username or Recovery Code.")
                else:
                    st.warning("Please fill all fields.")

    with t2:
        nu = st.text_input("New Username")
        np = st.text_input("New Passkey", type="password")
        
        with st.expander("📄 Terms of Service"):
            st.write("**1. Data Privacy:** We do not store your files or plain passkeys.")
            st.write("**2. Recovery:** Resetting a passkey via recovery code will grant access to the account, but old encrypted data remains locked with the old key.")
        
        agree = st.checkbox("I accept the ADELL Tech Terms of Service.")
        
        if st.button("Generate Identity") and nu and np and agree:
            import secrets
            import string
            # Generate 12-character random code
            recovery_code = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(12))
            
            try:
                conn.table("users").insert({
                    "username": nu, 
                    "password": hashlib.sha256(np.encode()).hexdigest(), 
                    "recovery_code": recovery_code,
                    "op_count": 0, 
                    "payment_count": 0
                }).execute()
                
                st.success("✅ Identity Verified.")
                st.code(recovery_code, language="text") # Makes it easy to copy
                st.warning("⚠️ SAVE THIS CODE. It is the only way to reset your account.")
                
                # Downloadable backup for the user
                rec_txt = f"VANGUARD VAULT RECOVERY\nUser: {nu}\nCode: {recovery_code}"
                st.download_button("💾 DOWNLOAD RECOVERY KEY", rec_txt, f"Vault_Recovery_{nu}.txt")
                
            except Exception as e: 
                st.error("Username already exists or Database Error.")

else:
    # --- SIDEBAR ---
    with st.sidebar:
        # 1. The Branding & Pulse
        st.title("VANGUARD")
        show_status() # The cyan pulse from style.py
        
        # 2. Operator Info
        st.markdown(f"### OPERATOR: {st.session_state.user}")

# 3. Credits & Progress
userData = conn.table("users").select("*").eq("username", st.session_state.user).execute().data[0]
used, refills = userData['op_count'], userData.get('payment_count', 0)
st.progress(min(used/5, 1.0))
st.caption(f"Credits Remaining: {5 - used} / 5")

# --- USER TRANSACTION HISTORY ---
st.markdown("---")
st.subheader("🧾 Refill History")

try:
    # Fetch logs where the action contains 'REFILL' and the user is the logged-in user
    history = conn.table("logs").select("*").eq("username", st.session_state.user).ilike("action", "%REFILL%").order("timestamp", desc=True).execute().data
    
    if history:
        # Create a clean display for each transaction
        for item in history:
            date_str = item['timestamp'].split('T')[0] # Formats '2023-10-01'
            st.markdown(f"""
                <div style="background: #001a1d; padding: 8px; border-left: 3px solid #00f2ff; margin-bottom: 5px; border-radius: 4px;">
                    <span style="font-size: 0.75rem; color: #80ced6;">{date_str}</span><br>
                    <span style="font-size: 0.8rem; color: #00f2ff; font-weight: bold;">Refill Verified ✅</span>
                </div>
            """, unsafe_allow_html=True)
    else:
        st.caption("No transactions found yet.")
except Exception as e:
    st.caption("History currently unavailable.")

# 4. Receipts for Paid Users
if refills > 0:
    receipt = f"VANGUARD VAULT RECEIPT\nOperator: {st.session_state.user}\nRefills: {refills}\nDate: {datetime.now().strftime('%Y-%m-%d')}"
    st.download_button("📄 DOWNLOAD RECEIPT", receipt, f"Receipt_{st.session_state.user}.txt")
    
# 5. Navigation Menu
menu = ["AES Symmetric", "RSA Hybrid", "Steganography", "Hashing", "Diffie-Hellman", "ℹ️ About"]
if st.session_state.user == ADMIN_USERNAME: 
    menu.insert(0, "👑 ADMIN")
mode = st.selectbox("Select Module", menu)

# 6. User Security
with st.expander("👤 Security Settings"):
    old_p = st.text_input("Current Passkey", type="password")
    up_p = st.text_input("New Passkey", type="password")
    if st.button("Update Passkey"):
        if hashlib.sha256(old_p.encode()).hexdigest() == userData['password']:
            conn.table("users").update({"password": hashlib.sha256(up_p.encode()).hexdigest()}).eq("username", st.session_state.user).execute()
            st.success("Passkey Updated!")
        else: 
            st.error("Incorrect Current Passkey")

# 7. Session Control
if st.button("Terminate Session"):
    del st.session_state.user
    st.rerun()

    # --- AES MODULE ---
    if mode == "AES Symmetric":
        st.header("🛡️ AES-256 Symmetric Locker")
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
                        increment_usage("AES_TEXT_ENC")
                with col2:
                    ctxt = st.text_area("Ciphertext")
                    if st.button("Decrypt Text"):
                        try: st.success(f.decrypt(ctxt.encode()).decode())
                        except: st.error("Invalid Key")
            with t_file:
                up = st.file_uploader("Upload File")
                if up and st.button("🔒 Encrypt File") and check_usage_limit():
                    st.download_button(f"Download {up.name}.vanguard", f.encrypt(up.read()), f"{up.name}.vanguard")
                    increment_usage("AES_FILE_ENC")

    # --- RSA HYBRID ---
    elif mode == "RSA Hybrid":
        st.header("🔑 RSA Future-Proof Suite")
        
        tk, te, td = st.tabs(["🔑 KEYGEN", "🔒 ENCRYPT", "🔓 DECRYPT"])
        with tk:
            k_size = st.select_slider("Bit Strength", options=[2048, 3072, 4096], value=2048)
            if st.button("Generate RSA Pair") and check_usage_limit():
                priv = rsa.generate_private_key(65537, k_size)
                pem_pub = priv.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
                pem_priv = priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
                st.write("📤 **Public Key (Share This)**"); st.code(pem_pub)
                st.write("🔑 **Private Key (KEEP SECRET)**"); st.code(pem_priv)
                increment_usage(f"RSA_KEYGEN_{k_size}")
        with te:
            pub_in = st.text_area("Recipient Public Key")
            up_f = st.file_uploader("Select File/Video")
            if up_f and pub_in and st.button("Execute Hybrid Lock") and check_usage_limit():
                s_key = Fernet.generate_key()
                enc_file = Fernet(s_key).encrypt(up_f.read())
                pub = serialization.load_pem_public_key(pub_in.encode())
                enc_s_key = pub.encrypt(s_key, padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None))
                st.success("Vault Created!")
                st.code(base64.b64encode(enc_s_key).decode(), label="Recipient's Unlock Key")
                st.download_button("Download .vault", enc_file, f"{up_f.name}.vault")
                increment_usage("RSA_HYBRID_ENC")
        with td:
            priv_in = st.text_area("Your Private Key")
            cip_key = st.text_area("Encrypted Unlock Key")
            up_v = st.file_uploader("Upload .vault File")
            if st.button("Decrypt & Extract"):
                try:
                    priv = serialization.load_pem_private_key(priv_in.encode(), None)
                    s_key = priv.decrypt(base64.b64decode(cip_key.encode()), padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None))
                    st.download_button("Download Decrypted File", Fernet(s_key).decrypt(up_v.read()), "unlocked_file")
                except: st.error("Decryption Failed.")

    # --- STEGANOGRAPHY ---
    elif mode == "Steganography":
        st.header("🖼️ Steganographic Covert Ops")
        th, tx = st.tabs(["🔒 Hide Text", "🔓 Extract Text"])
        with th:
            img_up = st.file_uploader("Base Image", type=['png'])
            msg = st.text_area("Secret Message")
            if img_up and msg and st.button("Encode & Download") and check_usage_limit():
                buf = io.BytesIO()
                stepic.encode(Image.open(img_up), msg.encode()).save(buf, format="PNG")
                st.download_button("Download Secret PNG", buf.getvalue(), "secret.png")
                increment_usage("STEGO_HIDE")
        with tx:
            up_enc = st.file_uploader("Upload Encoded Image", type=['png'])
            if up_enc and st.button("Extract"):
                try: st.success(f"Hidden Message: {stepic.decode(Image.open(up_enc))}")
                except: st.error("No data found.")

            
    # --- Diffie-Hellman MODULE ---
            elif mode == "Diffie-Hellman":
                st.header("🤝 Diffie-Hellman Key Exchange")
                st.info("Establish a shared secret over an insecure channel.")
        
        from cryptography.hazmat.primitives.asymmetric import dh
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF

        # Standard 2048-bit MODP Group parameters
        param_numbers = dh.DHParameterNumbers(
            p=0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497C1B8E99408288D41D738908AF1305D157184E5321D50A22D1612984,
            g=2
        )
        parameters = param_numbers.parameters()

        t1, t2 = st.tabs(["1️⃣ Generate My Key", "2️⃣ Compute Shared Secret"])
        
        with t1:
            if st.button("Generate DH Public Key") and check_usage_limit():
                priv = parameters.generate_private_key()
                pub = priv.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
                # We store the private key in session state temporarily (unsaved to DB for security)
                st.session_state.dh_priv = priv 
                st.code(pub, label="Your DH Public Key (Send this to partner)")
                increment_usage("DH_KEYGEN")
        
        with t2:
            partner_pub_pem = st.text_area("Paste Partner's Public Key")
            if st.button("Calculate Secret") and partner_pub_pem:
                try:
                    partner_pub = serialization.load_pem_public_key(partner_pub_pem.encode())
                    shared_key = st.session_state.dh_priv.exchange(partner_pub)
                    # Derive a usable key using HKDF
                    derived_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake').derive(shared_key)
                    st.success("🤝 Shared Secret Established!")
                    st.code(base64.urlsafe_b64encode(derived_key).decode(), label="Derived AES Key")
                except:
                    st.error("Invalid Partner Key or Private Key missing.")
    # --- HASHING MODULE ---
    elif mode == "Hashing":
        st.header("🔐 Secure Hash Generator")
        algo = st.selectbox("Select Hash Algorithm", ["SHA-256", "SHA-512", "MD5"])
        inp_txt = st.text_area("Input Text")
        
        if st.button("Generate Hash") and inp_txt:
            if algo == "SHA-256":
                digest = hashlib.sha256(inp_txt.encode()).hexdigest()
            elif algo == "SHA-512":
                digest = hashlib.sha512(inp_txt.encode()).hexdigest()
            else: # MD5
                digest = hashlib.md5(inp_txt.encode()).hexdigest()
            st.code(digest, label=f"{algo} Hash")
            increment_usage(f"HASH_{algo.replace('-', '')}")

    # --- HELP AND SUPPORT ---

    elif mode == "📡 Support":
        st.header("📡 Secure Communication Channel")
        st.info("Submit a priority ticket to ADELL Tech Command.")
        
        with st.form("ticket_form", clear_on_submit=True):
            sub = st.selectbox("Subject", ["Payment Issue", "Technical Bug", "Feature Request", "Other"])
            msg = st.text_area("Detailed Message")
            
            if st.form_submit_button("Transmit Ticket"):
                if msg:
                    conn.table("support_tickets").insert({
                        "username": st.session_state.user,
                        "subject": sub,
                        "message": msg
                    }).execute()
                    st.success("🛰️ Signal Transmitted. Admin will review your case.")
                    add_log(st.session_state.user, "SUPPORT_TICKET_SENT")
                else:
                    st.error("Message body cannot be empty.")

    # --- ABOUT MODULE ---
    elif mode == "ℹ️ About":
        st.header("🛡️ VANGUARD VAULT | SYSTEM OVERVIEW")
        st.success("✅ **Zero-Knowledge Architecture:** ADELL Tech does not store your Passkey. Your security is mathematically guaranteed.")
        
        # --- THE CRITICAL SECURITY NOTE ---
        st.warning("""
        ⚠️ **CRITICAL NOTE ON DECRYPTION:** While your Recovery Code can reset your **Account Access**, it CANNOT recover files encrypted with a lost Master Password. 
        In true Zero-Knowledge systems, if you lose the specific password used to lock a file, that data is mathematically lost forever. 
        **Vanguard Vault staff cannot 'backdoor' your files.**
        """)

        col1, col2 = st.columns([2, 1])
        with col1:
            st.markdown(f"""
### **1. Identity & Data Recovery**
* **Account Recovery:** Use your 12-character code to reset your login passkey if forgotten.
* **Data Locking:** We log action types (e.g., 'AES_ENC') for billing, but we never see your files.

### **2. RSA Hybrid & Diffie-Hellman**
* **RSA:** Securely send files by locking them with a recipient's **Public Key**.
* **DH Exchange:** Establish a shared secret key with a partner in real-time without revealing private data.


### **3. Hashing & Steganography**
* **Hashing:** Generate 'fingerprints' to verify if a file has been tampered with.
* **Stego:** We hide data in pixels. **Tip:** Always send Stego images as a **'Document'** on WhatsApp to prevent compression.


### **4. How to Transfer Secure Files**
1. **Encrypt** your file/text inside the Vault.
2. **Download** the resulting `.vanguard` or `.vault` file to your device.
3. **Send** that file to your partner via any chat app.
4. Your partner **Uploads** that file into their Vault and enters the key to Decrypt.
            """)
        with col2:
            st.info(f"**Developer:** ADELL Tech\n\n**BANK INFO:**\n{BANK_INFO}")
            st.image("https://img.icons8.com/fluency/100/verified-badge.png")

    # --- ADMIN ---
    elif mode == "👑 ADMIN":
        st.header("🛡️ COMMAND CENTER")
        
        # 1. Fetch Data
        logs = conn.table("logs").select("*").order("timestamp", desc=True).execute().data
        users = conn.table("users").select("*").execute().data
        df_logs = pd.DataFrame(logs)
        df_users = pd.DataFrame(users)
        
        # 2. Key Metrics Row
        col1, col2, col3 = st.columns(3)
        with col1:
            total_rev = df_users['payment_count'].sum() * 200
            st.metric("Total Revenue", f"₦{total_rev:,}")
        with col2:
            st.metric("Active Operators", len(df_users))
        with col3:
            # Counts how many times 'ENC' appears in logs
            actions = df_logs[df_logs['action'].str.contains('ENC|LOCK', na=False)]
            st.metric("Total Encryptions", len(actions))

        # 3. Live Activity Feed
        st.subheader("🕵️ Live System Logs")
        st.dataframe(df_logs[['username', 'action', 'timestamp']].head(10), use_container_width=True)
        
        # 4. User Management & Manual Refill
        st.subheader("👤 Operator Management")
        target = st.selectbox("Select Operator to Refill", df_users['username'].tolist())
        
        if st.button("✅ VERIFY & REFILL (₦200)"):
            # Get current payment count to increment it
            curr_p = df_users[df_users['username'] == target]['payment_count'].values[0]
            conn.table("users").update({
                "op_count": 0, 
                "payment_count": int(curr_p + 1)
            }).eq("username", target).execute()
            
            # Log the refill event
            add_log(ADMIN_USERNAME, f"REFILLED_{target}")
            st.success(f"Credits restored for {target}. Payment recorded.")
            st.rerun()
        # 5. Support Ticket Monitoring
        st.markdown("---")
        st.subheader("📡 Incoming Support Signals")
        
        # Fetch only tickets that haven't been resolved yet
        tickets = conn.table("support_tickets").select("*").eq("status", "OPEN").execute().data
        
        if tickets:
            for t in tickets:
                # Expander keeps the UI clean if you have many tickets
                with st.expander(f"Ticket from {t['username']} - {t['subject']}"):
                    st.write(f"**Message:** {t['message']}")
                    st.caption(f"Received: {t['timestamp']}")
                    
                    # Button to close the ticket
                    if st.button(f"Mark Ticket {t['id']} as Resolved", key=f"res_{t['id']}"):
                        conn.table("support_tickets").update({"status": "RESOLVED"}).eq("id", t['id']).execute()
                        st.success("Ticket cleared.")
                        st.rerun()
        else:
            st.success("No pending support tickets. Systems optimal.")