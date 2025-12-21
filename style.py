import streamlit as st

def apply_custom_theme():
    """
    Applies the Vanguard Vault signature Deep Cyan & Neon Glow theme.
    """
    st.markdown("""
        <style>
        /* Main App Background - Deep Cyan Abyss */
        .stApp {
            background-color: #00080a;
            background-image: radial-gradient(circle at 50% 50%, #001a1a 0%, #00080a 100%);
            color: #e0faff;
        }

        /* Sidebar Styling */
        section[data-testid="stSidebar"] {
            background-color: #000506;
            border-right: 1px solid #00f2ff33;
        }

        /* Headers and Titles */
        h1, h2, h3 {
            color: #00f2ff !important;
            font-family: 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            text-transform: uppercase;
            letter-spacing: 2px;
            text-shadow: 0 0 15px rgba(0, 242, 255, 0.4);
        }

        /* Neon Cyan Buttons */
        .stButton>button {
            width: 100%;
            border-radius: 4px;
            background-color: transparent;
            color: #00f2ff;
            border: 1px solid #00f2ff;
            transition: all 0.3s ease-in-out;
            font-weight: bold;
        }

        .stButton>button:hover {
            background-color: #00f2ff1a;
            color: #ffffff;
            border: 1px solid #ffffff;
            box-shadow: 0 0 12px #00f2ff;
        }

        /* Input Fields - Darkened Cyan */
        .stTextInput>div>div>input, .stTextArea>div>div>textarea {
            background-color: #001215 !important;
            color: #00f2ff !important;
            border: 1px solid #00f2ff44 !important;
            border-radius: 4px;
        }

        /* Progress Bar */
        .stProgress > div > div > div > div {
            background-image: linear-gradient(to right, #004d4d, #00f2ff);
        }

        /* Tabs Styling */
        .stTabs [data-baseweb="tab"] {
            color: #80ced6;
        }

        .stTabs [aria-selected="true"] {
            color: #00f2ff !important;
            border-bottom-color: #00f2ff !important;
        }

        /* Success Messages */
        .stAlert {
            background-color: #001215;
            border: 1px solid #00ffaa;
            color: #00ffaa;
        }
        </style>
    """, unsafe_allow_html=True)

def show_status():
    """
    Displays the 'SYSTEM ONLINE' pulse indicator with Cyan Glow.
    """
    st.sidebar.markdown("""
        <div style="display: flex; align-items: center; padding: 12px; border: 1px solid #00f2ff22; border-radius: 4px; background: #000c0e;">
            <div style="
                width: 10px; 
                height: 10px; 
                background-color: #00f2ff; 
                border-radius: 50%; 
                margin-right: 12px;
                box-shadow: 0 0 15px #00f2ff;
                animation: scan 2s infinite;">
            </div>
            <span style="color: #00f2ff; font-family: monospace; font-size: 0.75rem; letter-spacing: 1px;">CORE VANGUARD: ACTIVE</span>
        </div>
        
        <style>
        @keyframes scan {
            0% { opacity: 1; box-shadow: 0 0 5px #00f2ff; }
            50% { opacity: 0.4; box-shadow: 0 0 20px #00f2ff; }
            100% { opacity: 1; box-shadow: 0 0 5px #00f2ff; }
        }
        </style>
    """, unsafe_allow_html=True)