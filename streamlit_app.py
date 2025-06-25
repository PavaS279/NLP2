import streamlit as st
import requests
import os
import base64
import hashlib
import secrets
import urllib.parse

# ------------------------- Configuration -------------------------
SF_CLIENT_ID = st.secrets["oauth"]["SF_CLIENT_ID"]
SF_REDIRECT_URI = "https://nlp-dashboard-2.streamlit.app/oauth/callback"
SF_AUTH_URL = "https://login.salesforce.com/services/oauth2/authorize"
SF_TOKEN_URL = "https://login.salesforce.com/services/oauth2/token"

# ------------------------- PKCE Helper ---------------------------
def generate_pkce_pair():
    code_verifier = base64.urlsafe_b64encode(os.urandom(40)).rstrip(b'=').decode('utf-8')
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode()).digest()
    ).rstrip(b'=').decode('utf-8')
    return code_verifier, code_challenge

# ------------------------- Auth URL Generator ---------------------
def get_salesforce_login_url():
    code_verifier, code_challenge = generate_pkce_pair()
    state = secrets.token_urlsafe(16)

    st.session_state["oauth_state"] = state
    st.session_state["pkce_verifier"] = code_verifier

    params = {
        "response_type": "code",
        "client_id": SF_CLIENT_ID,
        "redirect_uri": SF_REDIRECT_URI,
        "scope": "openid profile email",
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256"
    }
    return f"{SF_AUTH_URL}?{urllib.parse.urlencode(params)}"

# ------------------------- Token Exchange -------------------------
def handle_salesforce_callback():
    query_params = st.query_params
    code = query_params.get("code")
    state = query_params.get("state")

    if not code:
        st.error("Missing authorization code.")
        return

    if "oauth_state" not in st.session_state or state != st.session_state["oauth_state"]:
        st.error("OAuth state mismatch.")
        return

    code_verifier = st.session_state.get("pkce_verifier")
    if not code_verifier:
        st.error("Missing code verifier in session.")
        return

    payload = {
        "grant_type": "authorization_code",
        "code": code,
        "client_id": SF_CLIENT_ID,
        "redirect_uri": SF_REDIRECT_URI,
        "code_verifier": code_verifier
    }

    with st.spinner("Exchanging code for tokens..."):
        response = requests.post(SF_TOKEN_URL, data=payload)

    if response.status_code == 200:
        tokens = response.json()
        st.session_state["salesforce_tokens"] = tokens
        st.success("✅ Logged in via Salesforce!")
        st.write(tokens)
    else:
        st.error(f"Token exchange failed: {response.text}")

# ------------------------- Main Streamlit App ---------------------
def main():
    st.title("🔐 Salesforce Login Demo with PKCE")

    query_params = st.query_params
    if "code" in query_params and "state" in query_params:
        handle_salesforce_callback()
        st.stop()

    if st.button("Login with Salesforce", use_container_width=True):
        login_url = get_salesforce_login_url()
        st.markdown(f"[Click here to login with Salesforce]({login_url})", unsafe_allow_html=True)

    # Show token if already logged in
    if "salesforce_tokens" in st.session_state:
        st.success("Already logged in")
        st.json(st.session_state["salesforce_tokens"])

if __name__ == "__main__":
    main()
