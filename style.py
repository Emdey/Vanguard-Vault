import streamlit as st

def apply_custom_theme():
    """Injects the Vanguard Vault High-End Cyberpunk UI."""
    st.markdown("""
        <style>
        /* Base Theme */
        .stApp {
            background-color: #00080a;
            background-image: radial-gradient(circle at 50% 50%, #001a1a 0%, #00080a 100%);
            color: #e0faff;
        }

        /* Sidebar Glassmorphism */
        section[data-testid="stSidebar"] {
            background-color: #000506 !important;
            border-right: 1px solid #00f2ff33 !important;
        }

        /* Neon Glow Headers */
        h1, h2, h3 {
            color: #00f2ff !important;
            text-transform: uppercase;
            letter-spacing: 2px;
            text-shadow: 0 0 15px rgba(0, 242, 255, 0.5);
        }

        /* Cyber Buttons */
        .stButton>button {
            width: 100%;
            border-radius: 2px;
            background-color: transparent;
            color: #00f2ff;
            border: 1px solid #00f2ff;
            transition: 0.3s;
            font-weight: bold;
            text-transform: uppercase;
        }

        .stButton>button:hover {
            background-color: #00f2ff1a;
            box-shadow: 0 0 15px #00f2ff;
            color: white;
            border: 1px solid white;
        }

        /* Payment Buttons */
        .flutterwave-btn {
            background: linear-gradient(135deg, #fbba00, #ff8c00) !important;
            color: black !important;
            padding: 12px;
            border-radius: 5px;
            font-weight: 800;
            text-decoration: none;
            display: block;
            text-align: center;
            box-shadow: 0 4px 15px rgba(251, 186, 0, 0.3);
        }

        .whatsapp-btn {
            background: #25D366 !important;
            color: white !important;
            padding: 12px;
            border-radius: 5px;
            font-weight: 800;
            text-decoration: none;
            display: block;
            text-align: center;
            margin-top: 10px;
        }

        /* Glowing Inputs */
        .stTextInput>div>div>input, .stTextArea>div>div>textarea {
            background-color: #001215 !important;
            color: #00f2ff !important;
            border: 1px solid #00f2ff33 !important;
        }

        .stTextInput>div>div>input:focus {
            border: 1px solid #00f2ff !important;
            box-shadow: 0 0 10px #00f2ff44;
        }

        /* Support Ticket Cards */
        .support-card {
            background:#001215;
            padding:20px;
            border:2px solid #00f2ff;
            border-radius:8px;
            margin-bottom:12px;
        }

        /* Badge Styles */
        .badge-open { background:#FF6B6B; color:white; padding:4px 8px; border-radius:4px; }
        .badge-resolved { background:#4ECDC4; color:white; padding:4px 8px; border-radius:4px; }
        .badge-unknown { background:#FFD93D; color:black; padding:4px 8px; border-radius:4px; }

        /* Sidebar Status Pulse */
        .pulse {
            width: 10px; height: 10px; background: #00f2ff; border-radius: 50%; margin-right: 12px;
            box-shadow: 0 0 10px #00f2ff; animation: blink 1.5s infinite;
        }
        @keyframes blink { 0% { opacity: 1; } 50% { opacity: 0.3; } 100% { opacity: 1; } }
        </style>
    """, unsafe_allow_html=True)

def show_status():
    """The Active System Pulse."""
    st.sidebar.markdown("""
        <div style="display: flex; align-items: center; padding: 12px; border: 1px solid #00f2ff33; border-radius: 4px; background: rgba(0, 242, 255, 0.05); margin-bottom: 20px;">
            <div class="pulse"></div>
            <span style="color: #00f2ff; font-family: monospace; font-size: 0.8rem; font-weight: bold;">CORE VANGUARD: ACTIVE</span>
        </div>
    """, unsafe_allow_html=True)
