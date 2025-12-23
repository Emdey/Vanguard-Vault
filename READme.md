
```markdown
# 🛡️ VANGUARD VAULT | ADELL Tech
### **Military-Grade Encryption & Secure Data Management Suite**

Vanguard Vault is a professional-grade cryptographic platform. It combines high-level security with a seamless business model, allowing users to protect sensitive data using the world's most trusted algorithms.

---

## 🚀 System Capabilities

* **AES-256 Symmetric Locking:** Fast, high-security encryption for files, documents, and videos.
* **RSA-4096 Hybrid Suite:** State-of-the-art asymmetric encryption for secure file sharing.
* **Steganography Ops:** Hide secret text inside PNG images with zero visual distortion.
* **Zero-Knowledge Identity:** Passkeys are never stored in plaintext. If you lose your key, even we cannot access your data.
* **Professional Billing:** Integrated payment verification for service refills (₦200/pack).

---

## 🛠️ Technical Stack

| Component | Technology |
| :--- | :--- |
| **Language** | Python 3.9+ |
| **Framework** | Streamlit |
| **Database** | Supabase (PostgreSQL) |
| **Encryption** | Cryptography.io (Fernet & Hazmat) |
| **Stego** | Stepic & Pillow |

---

## 📂 Project Structure

```text
├── app.py                # Main application logic & Encryption Engine
├── style.py              # UI/UX Theme (Deep Cyan & Neon Glow)
├── requirements.txt      # System dependencies
└── .streamlit/
    └── secrets.toml      # Database credentials (Keys)

```

---

## ⚙️ Installation

1. **Clone the repository**
```bash
git clone [https://github.com/your-username/vanguard-vault.git](https://github.com/your-username/vanguard-vault.git)

```


2. **Install requirements**
```bash
pip install -r requirements.txt

```


3. **Database Setup**
Run the following SQL in your Supabase editor to initialize the logs:
```sql
CREATE TABLE logs (
  id uuid DEFAULT gen_random_uuid() PRIMARY KEY,
  username text,
  action text,
  timestamp timestamp with time zone DEFAULT now()
);

```


4. **Run the app**
```bash
streamlit run app.py

```



---

## 💼 Business Operations (ADELL Tech)

**Vanguard Vault** uses a credit-based system:

1. **Free Tier:** 5 operations allowed upon registration.
2. **Refill Process:** User pays ₦200 to the bank details in the sidebar.
3. **Verification:** User sends proof to WhatsApp (+234 705 919 4126).
4. **Admin Action:** Operator is refilled via the hidden Admin Command Center.

---

## ⚖️ Disclaimer

**ADELL Tech** provides the tools, but the user provides the security. We do not store keys. Lost keys = Permanent data loss. Use responsibly.

---

**Developed by ADELL Tech** *Securing the Digital Frontier.*

```

