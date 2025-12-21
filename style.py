import streamlit as st

def apply_custom_theme():
    """
    Midnight Glass UI with 'Deep Sea Cyan' accents. 
    Optimized for eye comfort and professional aesthetics.
    """
    st.markdown("""
        <style>
        /* 1. Deep Midnight Blue Background */
        .stApp {
            background: radial-gradient(circle at top, #06101f 0%, #020811 100%);
            color: #d1d9e0;
        }
        
        /* 2. Soft Glassmorphism Panels */
        [data-testid="stVerticalBlock"] > div > div > div {
            background: rgba(255, 255, 255, 0.02);
            backdrop-filter: blur(12px);
            -webkit-backdrop-filter: blur(12px);
            border-radius: 12px;
            border: 1px solid rgba(0, 212, 255, 0.08);
            padding: 25px;
            margin-bottom: 15px;
        }

        /* 3. Sidebar Glass Effect */
        section[data-testid="stSidebar"] {
            background-color: rgba(4, 12, 24, 0.85) !important;
            backdrop-filter: blur(20px);
            border-right: 1px solid rgba(0, 212, 255, 0.1);
        }

        /* 4. Deep Sea Cyan Buttons */
        .stButton>button {
            background: rgba(0, 180, 216, 0.05);
            color: #00b4d8;
            border: 1px solid rgba(0, 180, 216, 0.4);
            border-radius: 6px;
            transition: all 0.4s ease;
            font-weight: 500;
        }
        
        .stButton>button:hover {
            background: rgba(0, 180, 216, 0.2);
            color: #ffffff;
            border: 1px solid #00d4ff;
            box-shadow: 0 0 15px rgba(0, 212, 255, 0.3);
        }

        /* 5. Blinking Status Dot */
        .status-dot {
            height: 10px; width: 10px;
            background-color: #00ff88;
            border-radius: 50%;
            display: inline-block;
            margin-right: 8px;
            box-shadow: 0 0 8px #00ff88;
            animation: blink 2s infinite;
        }

        @keyframes blink {
            0% { opacity: 1; }
            50% { opacity: 0.3; }
            100% { opacity: 1; }
        }

        /* 6. Inputs - Dark & Inset */
        .stTextInput>div>div>input, .stTextArea>div>div>textarea {
            background-color: rgba(0, 0, 0, 0.3) !important;
            color: #00b4d8 !important;
            border: 1px solid rgba(0, 180, 216, 0.2) !important;
        }

        h1, h2, h3 {
            color: #ffffff !important;
            font-weight: 300;
            letter-spacing: -0.5px;
        }

        /* Tab Styling */
        .stTabs [data-baseweb="tab-list"] { gap: 10px; }
        .stTabs [data-baseweb="tab"] {
            background-color: transparent;
            color: #8892b0;
        }
        .stTabs [aria-selected="true"] {
            color: #00d4ff !important;
            border-bottom-color: #00d4ff !important;
        }

        #MainMenu, footer {visibility: hidden;}
        </style>
        """, unsafe_allow_html=True)

def show_status():
    """Call this in the sidebar to show the live status indicator"""
    st.sidebar.markdown('<div><span class="status-dot"></span><span style="color: #00ff88; font-size: 14px; font-weight: bold;">SYSTEM ACTIVE</span></div>', unsafe_allow_html=True)