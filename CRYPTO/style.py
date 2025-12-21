import streamlit as st

def apply_custom_theme():
    """
    Injects professional 'Cybersecurity Command Center' CSS 
    into the Streamlit app.
    """
    st.markdown("""
        <style>
        /* Main background and text */
        .stApp {
            background-color: #0e1117;
            color: #e0e0e0;
        }
        
        /* Headers */
        h1, h2, h3 {
            color: #00d4ff !important;
            font-family: 'Courier New', Courier, monospace;
        }
        
        /* Buttons */
        .stButton>button {
            background-color: #1f2937;
            color: #00d4ff;
            border: 1px solid #00d4ff;
            border-radius: 5px;
            transition: all 0.3s;
            width: 100%;
        }
        .stButton>button:hover {
            background-color: #00d4ff;
            color: #0e1117;
            box-shadow: 0 0 15px #00d4ff;
        }
        
        /* Sidebar styling */
        section[data-testid="stSidebar"] {
            background-color: #161b22;
            border-right: 1px solid #30363d;
        }
        
        /* Tabs Styling */
        .stTabs [data-baseweb="tab-list"] {
            gap: 24px;
        }
        .stTabs [data-baseweb="tab"] {
            height: 50px;
            background-color: transparent;
            color: #8b949e;
        }
        .stTabs [aria-selected="true"] {
            background-color: #1f2937 !important;
            color: #00d4ff !important;
            border-bottom: 2px solid #00d4ff !important;
        }
        
        /* Input Fields */
        input, textarea {
            background-color: #0d1117 !important;
            color: #00d4ff !important;
            border: 1px solid #30363d !important;
        }

        /* Success/Error override */
        .stAlert {
            background-color: #161b22;
            border: 1px solid #30363d;
        }
        </style>
        """, unsafe_allow_html=True)