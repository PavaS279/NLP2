import streamlit as st
import requests
import os
import hashlib
import base64
import json
from urllib.parse import urlencode

# ======================== CONFIGURATION ============================
SF_AUTH_URL = "https://login.salesforce.com/services/oauth2/authorize"
SF_TOKEN_URL = "https://login.salesforce.com/services/oauth2/token"
SF_API_BASE = "https://your_instance.salesforce.com/services/data/v59.0"
REDIRECT_URI = "https://nlp-dashboard-2.streamlit.app/oauth/callback"

# From Streamlit secrets
SF_CLIENT_ID = st.secrets["oauth"]["SF_CLIENT_ID"]
SF_CLIENT_SECRET = st.secrets["oauth"]["SF_CLIENT_SECRET"]

# ======================== UTILITIES ============================
def generate_pkce_pair():
    code_verifier = base64.urlsafe_b64encode(os.urandom(40)).decode("utf-8").rstrip("=")
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode()).digest()
    ).decode("utf-8").rstrip("=")
    return code_verifier, code_challenge

def get_salesforce_login_url():
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
        "scope": "openid profile email",
        "state": state,
    }
    return f"{SF_AUTH_URL}?{urlencode(params)}"

def handle_salesforce_callback(code):
    with st.spinner("🔐 Exchanging token with Salesforce..."):
        data = {
            "grant_type": "authorization_code",
            "client_id": SF_CLIENT_ID,
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "code_verifier": st.session_state.get("code_verifier"),
        }
        response = requests.post(SF_TOKEN_URL, data=data)

        if response.status_code != 200:
            st.error(f"❌ Token exchange failed: {response.text}")
            st.stop()

        token_data = response.json()
        st.session_state["access_token"] = token_data["access_token"]
        st.session_state["instance_url"] = token_data["instance_url"]
        st.success("✅ Logged in with Salesforce successfully.")

# ======================== SALESFORCE API ============================
def fetch_salesforce_accounts():
    access_token = st.session_state.get("access_token")
    instance_url = st.session_state.get("instance_url")

    if not access_token or not instance_url:
        st.error("You are not authenticated.")
        return

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }
    with st.spinner("📡 Fetching accounts from Salesforce..."):
        response = requests.get(
            f"{instance_url}/services/data/v59.0/query/", 
            headers=headers,
            params={"q": "SELECT Id, Name, Type, Industry FROM Account LIMIT 20"}
        )

        if response.status_code == 200:
            records = response.json().get("records", [])
            return records
        else:
            st.error(f"❌ Failed to fetch accounts: {response.text}")
            return []

# ======================== UI HANDLING ============================
def show_account_data():
    accounts = fetch_salesforce_accounts()
    if accounts:
        st.success("✅ Retrieved Account Records")
        st.dataframe(accounts, use_container_width=True)

def main():
    st.set_page_config(page_title="Salesforce OAuth Demo", layout="centered")
    st.title("🔐 Salesforce OAuth2 + PKCE Integration")

    # Handle callback
    query_params = st.query_params
    if "code" in query_params and "state" in query_params:
        if "oauth_state" in st.session_state and query_params["state"] == st.session_state["oauth_state"]:
            handle_salesforce_callback(query_params["code"])
            st.rerun()
        else:
            st.error("🔐 Invalid OAuth state.")
            st.stop()

    if "access_token" in st.session_state:
        st.success("🔓 Authenticated with Salesforce")
        show_account_data()
    else:
        if st.button("Login with Salesforce", use_container_width=True):
            login_url = get_salesforce_login_url()
            st.markdown(f"[🔗 Click here to login with Salesforce]({login_url})")

if __name__ == "__main__":
    main()
