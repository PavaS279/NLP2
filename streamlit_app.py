import streamlit as st
import requests
import os
import hashlib
import base64
import json
import time
from urllib.parse import urlencode
import asyncio
from datetime import datetime

# ======================== CONFIGURATION ============================
SF_AUTH_URL = "https://login.salesforce.com/services/oauth2/authorize"
SF_TOKEN_URL = "https://login.salesforce.com/services/oauth2/token"
SF_API_BASE = "https://orgfarm-946eb54298-dev-ed.develop.my.salesforce.com/services/data/v59.0"
REDIRECT_URI = "https://nlp-dashboard-2.streamlit.app/oauth/callback"

# From Streamlit secrets
SF_CLIENT_ID = st.secrets["oauth"]["SF_CLIENT_ID"]
SF_CLIENT_SECRET = st.secrets["oauth"]["SF_CLIENT_SECRET"]

# ======================== CUSTOM CSS ============================
def load_custom_css():
    st.markdown("""
    <style>
    /* Main container styling */
    .main-container {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        min-height: 100vh;
        padding: 2rem 0;
    }
    
    /* Login card styling */
    .login-card {
        background: rgba(255, 255, 255, 0.95);
        backdrop-filter: blur(10px);
        border-radius: 20px;
        padding: 3rem 2rem;
        box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
        border: 1px solid rgba(255, 255, 255, 0.2);
        max-width: 500px;
        margin: 0 auto;
        text-align: center;
    }
    
    /* Title styling */
    .app-title {
        font-size: 2.5rem;
        font-weight: 700;
        color: #2c3e50;
        margin-bottom: 1rem;
        text-shadow: 2px 2px 4px rgba(0, 0, 0, 0.1);
    }
    
    .app-subtitle {
        font-size: 1.2rem;
        color: #7f8c8d;
        margin-bottom: 2rem;
        font-weight: 300;
    }
    
    /* Custom button styling */
    .stButton > button {
        width: 100%;
        background: linear-gradient(45deg, #00d4ff, #0099cc);
        color: white;
        border: none;
        padding: 1rem 2rem;
        border-radius: 50px;
        font-size: 1.1rem;
        font-weight: 600;
        transition: all 0.3s ease;
        box-shadow: 0 4px 15px rgba(0, 153, 204, 0.3);
    }
    
    .stButton > button:hover {
        transform: translateY(-2px);
        box-shadow: 0 6px 20px rgba(0, 153, 204, 0.4);
        background: linear-gradient(45deg, #0099cc, #00d4ff);
    }
    
    /* Loading spinner styling */
    .loading-container {
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        padding: 2rem;
        background: rgba(255, 255, 255, 0.9);
        border-radius: 15px;
        margin: 1rem 0;
        box-shadow: 0 10px 25px rgba(0, 0, 0, 0.1);
    }
    
    .loading-spinner {
        width: 50px;
        height: 50px;
        border: 4px solid #f3f3f3;
        border-top: 4px solid #00d4ff;
        border-radius: 50%;
        animation: spin 1s linear infinite;
        margin-bottom: 1rem;
    }
    
    @keyframes spin {
        0% { transform: rotate(0deg); }
        100% { transform: rotate(360deg); }
    }
    
    .loading-text {
        font-size: 1.1rem;
        color: #2c3e50;
        font-weight: 600;
        text-align: center;
    }
    
    /* Success message styling */
    .success-message {
        background: linear-gradient(45deg, #2ecc71, #27ae60);
        color: white;
        padding: 1rem;
        border-radius: 10px;
        text-align: center;
        font-weight: 600;
        margin: 1rem 0;
        box-shadow: 0 4px 15px rgba(46, 204, 113, 0.3);
    }
    
    /* Error message styling */
    .error-message {
        background: linear-gradient(45deg, #e74c3c, #c0392b);
        color: white;
        padding: 1rem;
        border-radius: 10px;
        text-align: center;
        font-weight: 600;
        margin: 1rem 0;
        box-shadow: 0 4px 15px rgba(231, 76, 60, 0.3);
    }
    
    /* Dashboard styling */
    .dashboard-header {
        background: linear-gradient(45deg, #3498db, #2980b9);
        color: white;
        padding: 2rem;
        border-radius: 15px;
        text-align: center;
        margin-bottom: 2rem;
        box-shadow: 0 10px 25px rgba(52, 152, 219, 0.3);
    }
    
    .dashboard-title {
        font-size: 2rem;
        font-weight: 700;
        margin-bottom: 0.5rem;
    }
    
    .dashboard-subtitle {
        font-size: 1.1rem;
        opacity: 0.9;
    }
    
    /* Chat container styling */
    .chat-container {
        background: white;
        border-radius: 15px;
        padding: 1.5rem;
        margin: 1rem 0;
        box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
        max-height: 400px;
        overflow-y: auto;
    }
    
    /* Data table styling */
    .stDataFrame {
        border-radius: 10px;
        overflow: hidden;
        box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
    }
    
    /* Hide default streamlit elements */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}
    
    /* Remove top padding */
    .block-container {
        padding-top: 1rem;
    }
    </style>
    """, unsafe_allow_html=True)

# ======================== UTILITIES ============================
def generate_pkce_pair():
    """Generate PKCE code verifier and challenge"""
    code_verifier = base64.urlsafe_b64encode(os.urandom(40)).decode("utf-8").rstrip("=")
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode()).digest()
    ).decode("utf-8").rstrip("=")
    return code_verifier, code_challenge

def show_loading_spinner(message="Loading..."):
    """Display custom loading spinner"""
    return st.markdown(f"""
    <div class="loading-container">
        <div class="loading-spinner"></div>
        <div class="loading-text">{message}</div>
    </div>
    """, unsafe_allow_html=True)

def show_success_message(message):
    """Display success message"""
    st.markdown(f'<div class="success-message">✅ {message}</div>', unsafe_allow_html=True)

def show_error_message(message):
    """Display error message"""
    st.markdown(f'<div class="error-message">❌ {message}</div>', unsafe_allow_html=True)

def progressive_loading(container, operation_name="Processing"):
    """Show progressive loading messages"""
    messages = [
        f"Please wait, analyzing your {operation_name.lower()}...",
        f"Hold on, it's taking more time to get data from database...",
        f"It's almost done, please hold on..."
    ]
    
    for i, message in enumerate(messages):
        if i == 0:
            time.sleep(5)
        elif i == 1:
            time.sleep(10)  # Total 15 seconds
        else:
            time.sleep(5)   # Total 20 seconds
            
        container.empty()
        with container:
            show_loading_spinner(message)

def get_salesforce_login_url():
    """Generate Salesforce OAuth login URL"""
    try:
        code_verifier, code_challenge = generate_pkce_pair()
        state = base64.urlsafe_b64encode(os.urandom(16)).decode("utf-8").rstrip("=")

        st.session_state["code_verifier"] = code_verifier
        st.session_state["oauth_state"] = state

        params = {
            "response_type": "code",
            "client_id": SF_CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "scope": "openid profile email api refresh_token",
            "state": state,
        }
        return f"{SF_AUTH_URL}?{urlencode(params)}"
    except Exception as e:
        st.error(f"Error generating login URL: {str(e)}")
        return None

def handle_salesforce_callback(code):
    """Handle OAuth callback and exchange code for token"""
    loading_container = st.empty()
    
    try:
        with loading_container:
            show_loading_spinner("🔐 Exchanging token with Salesforce...")
        
        data = {
            "grant_type": "authorization_code",
            "client_id": SF_CLIENT_ID,
            "client_secret": SF_CLIENT_SECRET,
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "code_verifier": st.session_state.get("code_verifier"),
        }
        
        response = requests.post(SF_TOKEN_URL, data=data, timeout=30)
        
        loading_container.empty()
        
        if response.status_code != 200:
            show_error_message(f"Token exchange failed: {response.text}")
            return False

        token_data = response.json()
        st.session_state["access_token"] = token_data["access_token"]
        st.session_state["instance_url"] = token_data["instance_url"]
        st.session_state["user_id"] = token_data.get("id", "")
        st.session_state["login_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        show_success_message("Logged in with Salesforce successfully!")
        time.sleep(2)  # Show success message briefly
        return True
        
    except requests.exceptions.Timeout:
        loading_container.empty()
        show_error_message("Request timeout. Please try again.")
        return False
    except Exception as e:
        loading_container.empty()
        show_error_message(f"Authentication error: {str(e)}")
        return False

# ======================== SALESFORCE API ============================
def fetch_salesforce_accounts():
    """Fetch Salesforce accounts with proper loading and error handling"""
    access_token = st.session_state.get("access_token")
    instance_url = st.session_state.get("instance_url")

    if not access_token or not instance_url:
        show_error_message("You are not authenticated. Please login first.")
        return []

    loading_container = st.empty()
    
    try:
        # Progressive loading
        with loading_container:
            show_loading_spinner("Please wait, analyzing your request...")
        time.sleep(3)
        
        with loading_container:
            show_loading_spinner("Hold on, it's taking more time to get data from database...")
        time.sleep(5)
        
        with loading_container:
            show_loading_spinner("It's almost done, please hold on...")
        
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        }
        
        response = requests.get(
            f"{instance_url}/services/data/v59.0/query/", 
            headers=headers,
            params={"q": "SELECT Id, Name, Type, Industry, Phone, Website FROM Account LIMIT 50"},
            timeout=30
        )
        
        loading_container.empty()
        
        if response.status_code == 200:
            records = response.json().get("records", [])
            show_success_message(f"Successfully retrieved {len(records)} account records!")
            return records
        elif response.status_code == 401:
            show_error_message("Authentication expired. Please login again.")
            # Clear session
            for key in ["access_token", "instance_url", "user_id"]:
                if key in st.session_state:
                    del st.session_state[key]
            return []
        else:
            show_error_message(f"Failed to fetch accounts: {response.text}")
            return []
            
    except requests.exceptions.Timeout:
        loading_container.empty()
        show_error_message("Request timeout. Please try again.")
        return []
    except Exception as e:
        loading_container.empty()
        show_error_message(f"Error fetching accounts: {str(e)}")
        return []

def fetch_salesforce_contacts():
    """Fetch Salesforce contacts"""
    access_token = st.session_state.get("access_token")
    instance_url = st.session_state.get("instance_url")

    if not access_token or not instance_url:
        show_error_message("You are not authenticated.")
        return []

    loading_container = st.empty()
    
    try:
        with loading_container:
            show_loading_spinner("Fetching contacts from Salesforce...")
        
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        }
        
        response = requests.get(
            f"{instance_url}/services/data/v59.0/query/", 
            headers=headers,
            params={"q": "SELECT Id, FirstName, LastName, Email, Phone, Account.Name FROM Contact LIMIT 50"},
            timeout=30
        )
        
        loading_container.empty()
        
        if response.status_code == 200:
            records = response.json().get("records", [])
            show_success_message(f"Successfully retrieved {len(records)} contact records!")
            return records
        else:
            show_error_message(f"Failed to fetch contacts: {response.text}")
            return []
            
    except Exception as e:
        loading_container.empty()
        show_error_message(f"Error fetching contacts: {str(e)}")
        return []

# ======================== UI COMPONENTS ============================
def show_login_page():
    """Display the login page with enhanced UI"""
    st.markdown('<div class="main-container">', unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        st.markdown("""
        <div class="login-card">
            <div class="app-title">🔐 Salesforce Connect</div>
            <div class="app-subtitle">Secure OAuth2 Integration with PKCE</div>
        </div>
        """, unsafe_allow_html=True)
        
        st.markdown("<br>", unsafe_allow_html=True)
        
        if st.button("🚀 Login with Salesforce", key="login_btn", use_container_width=True):
            with st.spinner("Generating secure login URL..."):
                login_url = get_salesforce_login_url()
                if login_url:
                    st.markdown(f"""
                    <div style="text-align: center; margin: 2rem 0;">
                        <a href="{login_url}" target="_self" style="
                            display: inline-block;
                            background: linear-gradient(45deg, #27ae60, #2ecc71);
                            color: white;
                            padding: 1rem 2rem;
                            text-decoration: none;
                            border-radius: 50px;
                            font-weight: 600;
                            font-size: 1.1rem;
                            box-shadow: 0 4px 15px rgba(39, 174, 96, 0.3);
                            transition: all 0.3s ease;
                        ">
                            🔗 Complete Login with Salesforce
                        </a>
                    </div>
                    """, unsafe_allow_html=True)
        
        # Add features section
        st.markdown("""
        <div style="margin-top: 3rem; text-align: center;">
            <h3 style="color: #2c3e50; margin-bottom: 1.5rem;">✨ Features</h3>
            <div style="display: flex; justify-content: space-around; flex-wrap: wrap;">
                <div style="margin: 0.5rem; padding: 1rem; background: rgba(255,255,255,0.8); border-radius: 10px;">
                    <strong>🔒 Secure Authentication</strong><br>
                    <small>OAuth2 with PKCE</small>
                </div>
                <div style="margin: 0.5rem; padding: 1rem; background: rgba(255,255,255,0.8); border-radius: 10px;">
                    <strong>📊 Real-time Data</strong><br>
                    <small>Live Salesforce sync</small>
                </div>
                <div style="margin: 0.5rem; padding: 1rem; background: rgba(255,255,255,0.8); border-radius: 10px;">
                    <strong>🚀 Fast Performance</strong><br>
                    <small>Optimized queries</small>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)
        
    st.markdown('</div>', unsafe_allow_html=True)

def show_dashboard():
    """Display the main dashboard after authentication"""
    # Dashboard header
    st.markdown(f"""
    <div class="dashboard-header">
        <div class="dashboard-title">Welcome to Salesforce Dashboard</div>
        <div class="dashboard-subtitle">Connected at {st.session_state.get('login_time', 'Unknown')}</div>
    </div>
    """, unsafe_allow_html=True)
    
    # Create tabs for different data views
    tab1, tab2, tab3 = st.tabs(["📊 Accounts", "👥 Contacts", "⚙️ Settings"])
    
    with tab1:
        st.subheader("Account Records")
        
        col1, col2 = st.columns([3, 1])
        with col2:
            if st.button("🔄 Refresh Accounts", use_container_width=True):
                accounts = fetch_salesforce_accounts()
                if accounts:
                    st.session_state["accounts_data"] = accounts
        
        with col1:
            if st.button("📥 Fetch Account Data", use_container_width=True):
                accounts = fetch_salesforce_accounts()
                if accounts:
                    st.session_state["accounts_data"] = accounts
        
        # Display accounts data
        if "accounts_data" in st.session_state and st.session_state["accounts_data"]:
            st.markdown("### 📋 Account Data")
            
            # Convert records for better display
            display_data = []
            for record in st.session_state["accounts_data"]:
                display_data.append({
                    "Name": record.get("Name", "N/A"),
                    "Type": record.get("Type", "N/A"),
                    "Industry": record.get("Industry", "N/A"),
                    "Phone": record.get("Phone", "N/A"),
                    "Website": record.get("Website", "N/A")
                })
            
            st.dataframe(display_data, use_container_width=True, height=400)
            
            # Add download option
            if st.button("📄 Download as CSV"):
                csv = pd.DataFrame(display_data).to_csv(index=False)
                st.download_button(
                    label="Download CSV",
                    data=csv,
                    file_name=f"salesforce_accounts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv"
                )
    
    with tab2:
        st.subheader("Contact Records")
        
        if st.button("📥 Fetch Contact Data", use_container_width=True):
            contacts = fetch_salesforce_contacts()
            if contacts:
                st.session_state["contacts_data"] = contacts
        
        if "contacts_data" in st.session_state and st.session_state["contacts_data"]:
            st.markdown("### 👥 Contact Data")
            
            display_data = []
            for record in st.session_state["contacts_data"]:
                display_data.append({
                    "First Name": record.get("FirstName", "N/A"),
                    "Last Name": record.get("LastName", "N/A"),
                    "Email": record.get("Email", "N/A"),
                    "Phone": record.get("Phone", "N/A"),
                    "Account": record.get("Account", {}).get("Name", "N/A") if record.get("Account") else "N/A"
                })
            
            st.dataframe(display_data, use_container_width=True, height=400)
    
    with tab3:
        st.subheader("Settings & Information")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("### 🔗 Connection Info")
            st.info(f"""
            **Instance URL:** {st.session_state.get('instance_url', 'N/A')}
            **Login Time:** {st.session_state.get('login_time', 'N/A')}
            **Status:** ✅ Connected
            """)
        
        with col2:
            st.markdown("### 🛠️ Actions")
            if st.button("🔓 Logout", use_container_width=True):
                # Clear all session data
                keys_to_clear = ["access_token", "instance_url", "user_id", "login_time", 
                               "accounts_data", "contacts_data", "code_verifier", "oauth_state"]
                for key in keys_to_clear:
                    if key in st.session_state:
                        del st.session_state[key]
                
                show_success_message("Successfully logged out!")
                time.sleep(1)
                st.rerun()

# ======================== MAIN APPLICATION ============================
def main():
    """Main application function"""
    # Page configuration
    st.set_page_config(
        page_title="Salesforce OAuth Dashboard",
        page_icon="🔐",
        layout="wide",
        initial_sidebar_state="collapsed"
    )
    
    # Load custom CSS
    load_custom_css()
    
    # Handle OAuth callback
    query_params = st.query_params
    if "code" in query_params and "state" in query_params:
        if ("oauth_state" in st.session_state and 
            query_params["state"] == st.session_state["oauth_state"]):
            
            if handle_salesforce_callback(query_params["code"]):
                # Clear query parameters and rerun
                st.query_params.clear()
                st.rerun()
        else:
            show_error_message("Invalid OAuth state. Please try logging in again.")
            # Clear any existing session data
            for key in list(st.session_state.keys()):
                if key.startswith(('oauth_', 'access_', 'instance_')):
                    del st.session_state[key]

    # Main application logic
    if "access_token" in st.session_state:
        show_dashboard()
    else:
        show_login_page()

if __name__ == "__main__":
    # Add pandas import for CSV functionality
    try:
        import pandas as pd
    except ImportError:
        st.error("pandas is required for CSV functionality. Please install it.")
    
    main()
