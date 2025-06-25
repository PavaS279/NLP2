import streamlit as st
import pandas as pd
import json
import hashlib
import secrets
import base64
import hashlib
import altair as alt
from datetime import datetime
from authlib.integrations.requests_client import OAuth2Session
from snowflake.snowpark.exceptions import SnowparkSQLException

# Snowflake session
cnx = st.connection("snowflake")
session = cnx.session()

# OAuth constants
SF_CLIENT_ID = st.secrets["oauth"]["SF_CLIENT_ID"]
SF_CLIENT_SECRET = st.secrets["oauth"]["SF_CLIENT_SECRET"]
REDIRECT_URI = "https://nlp-dashboard-2.streamlit.app/oauth/callback"
SF_AUTH_URL = "https://login.salesforce.com/services/oauth2/authorize"
SF_TOKEN_URL = "https://login.salesforce.com/services/oauth2/token"
SF_USERINFO_URL = "https://login.salesforce.com/services/oauth2/userinfo"

# App Config
st.set_page_config(page_title="Cortex Analyst Chat", page_icon="🤖", layout="wide")

CHAT_PROCEDURE = "CORTEX_ANALYST.CORTEX_AI.CORTEX_ANALYST_CHAT_PROCEDURE1"
DREMIO_PROCEDURE = "SALESFORCE_DREMIO.SALESFORCE_SCHEMA_DREMIO.DREMIO_DATA_PROCEDURE"
SEMANTIC_MODEL_PATH = "CORTEX_ANALYST.CORTEX_AI.CORTEX_ANALYST_STAGE/nlp.yaml"

# OAuth2 with PKCE
def generate_pkce_pair():
    code_verifier = secrets.token_urlsafe(64)
    code_challenge = base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest()).decode().rstrip("=")
    return code_verifier, code_challenge

def get_salesforce_login_url():
    code_verifier, code_challenge = generate_pkce_pair()
    st.session_state["code_verifier"] = code_verifier
    oauth = OAuth2Session(client_id=SF_CLIENT_ID, redirect_uri=REDIRECT_URI, code_challenge=code_challenge, code_challenge_method="S256")
    url, state = oauth.create_authorization_url(SF_AUTH_URL, scope="openid profile email")
    st.session_state["oauth_state"] = state
    return url

def handle_salesforce_callback():
    query_params = st.query_params
    if "code" in query_params:
        code = query_params["code"][0]
        code_verifier = st.session_state.get("code_verifier")
        oauth = OAuth2Session(
            client_id=SF_CLIENT_ID,
            client_secret=SF_CLIENT_SECRET,
            redirect_uri=REDIRECT_URI,
            code_verifier=code_verifier,
        )
        token = oauth.fetch_token(SF_TOKEN_URL, code=code)
        userinfo = oauth.get(SF_USERINFO_URL, token=token).json()
        email = userinfo.get("email")
        name = userinfo.get("name")
        st.session_state["logged_in"] = True
        st.session_state["username"] = name
        st.session_state["email"] = email
        st.success(f"✅ Welcome, {name}")
        st.rerun()

# Chat logic

def initialize_session_state():
    for key in ["messages", "user_messages", "active_suggestion", "message_counter", "data_sources_info", "chat_initialized", "processing", "pending_question"]:
        if key not in st.session_state:
            st.session_state[key] = [] if "messages" in key else None if key == "active_suggestion" else False

def call_cortex_analyst_procedure(user_message):
    try:
        messages_list = [{"role": "user", "content": [{"type": "text", "text": user_message}]}]
        result = session.call(CHAT_PROCEDURE, json.dumps(messages_list), SEMANTIC_MODEL_PATH)
        if not result:
            return None, "No response"
        response = json.loads(result)
        return (response.get("content", {}), None) if response.get("success", False) else (None, response.get("error_message"))
    except Exception as e:
        return None, str(e)

def call_dremio_data_procedure(sql):
    try:
        df = session.call(DREMIO_PROCEDURE, sql)
        return df.to_pandas() if hasattr(df, "to_pandas") else df, None
    except Exception as e:
        return None, str(e)

def extract_sql_from_response(response):
    try:
        for block in response.get("message", {}).get("content", []):
            if block.get("type") == "sql":
                return block.get("statement", "")
    except Exception:
        return None

def extract_text_from_response(response):
    try:
        return "\n".join(block.get("text", "") for block in response.get("message", {}).get("content", []) if block.get("type") == "text")
    except Exception:
        return ""

def display_charts_tab(df, key):
    if len(df.columns) < 2:
        st.warning("At least 2 columns are required.")
        return
    x_col = st.selectbox("X axis", df.columns, key=f"x_{key}")
    y_col = st.selectbox("Y axis", [col for col in df.columns if col != x_col], key=f"y_{key}")
    chart_type = st.selectbox("Chart type", ["Line Chart", "Bar Chart", "Pie Chart"], key=f"type_{key}")
    data = df[[x_col, y_col]].dropna()
    if chart_type == "Line Chart":
        st.line_chart(data.set_index(x_col))
    elif chart_type == "Bar Chart":
        st.bar_chart(data.set_index(x_col))
    elif chart_type == "Pie Chart":
        pie = alt.Chart(data).mark_arc().encode(theta=alt.Theta(field=y_col, type="quantitative"), color=alt.Color(field=x_col, type="nominal"))
        st.altair_chart(pie, use_container_width=True)

def process_user_question(question):
    st.session_state.processing = True
    st.chat_message("user").markdown(question)
    with st.chat_message("assistant"):
        with st.spinner("Please wait, analyzing your question..."):
            response, error = call_cortex_analyst_procedure(question)
            if error or not response:
                st.error(error or "Unknown error")
                return
            text = extract_text_from_response(response)
            if text:
                st.markdown(text)
            sql = extract_sql_from_response(response)
            if sql:
                df, err = call_dremio_data_procedure(sql)
                if df is not None:
                    tab1, tab2 = st.tabs(["Data", "Chart"])
                    with tab1:
                        st.dataframe(df, use_container_width=True)
                    with tab2:
                        display_charts_tab(df, hashlib.md5(sql.encode()).hexdigest()[:8])
                elif err:
                    st.error(f"SQL Error: {err}")
    st.session_state.processing = False

def render_chat():
    st.title("🤖 NLP-Powered Data Chat")
    for msg in st.session_state.get("messages", []):
        st.chat_message(msg["role"]).markdown(msg["content"])
    user_input = st.chat_input("Ask about your data...", disabled=st.session_state.processing)
    if user_input:
        st.session_state["messages"].append({"role": "user", "content": user_input})
        process_user_question(user_input)

def login_signup_interface():
    st.title("🔐 Cortex Analyst Login")
    st.subheader("Login with your credentials or use Salesforce")
    if st.button("Login with Salesforce"):
        login_url = get_salesforce_login_url()
        st.markdown(f"[Click here to login with Salesforce]({login_url})", unsafe_allow_html=True)
    st.stop()

def main():
    query_params = st.query_params()
    if "code" in query_params and "oauth_state" in st.session_state:
        handle_salesforce_callback()
        return
    if not st.session_state.get("logged_in"):
        login_signup_interface()
    initialize_session_state()
    render_chat()

if __name__ == "__main__":
    main()
