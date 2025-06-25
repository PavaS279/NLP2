# Modified Streamlit App with Login/Signup UI and Enhanced Loading/UX

import json
import streamlit as st
import pandas as pd
from snowflake.snowpark.exceptions import SnowparkSQLException
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import altair as alt
import numpy as np
import re
import hashlib
import uuid
import bcrypt
import time

# Snowflake connection
cnx = st.connection("snowflake")
session = cnx.session()

# Configuration
SEMANTIC_MODEL_PATH = "CORTEX_ANALYST.CORTEX_AI.CORTEX_ANALYST_STAGE/nlp.yaml"
CHAT_PROCEDURE = "CORTEX_ANALYST.CORTEX_AI.CORTEX_ANALYST_CHAT_PROCEDURE1"
DREMIO_PROCEDURE = "SALESFORCE_DREMIO.SALESFORCE_SCHEMA_DREMIO.DREMIO_DATA_PROCEDURE"

st.set_page_config(page_title="Cortex Analyst Chat", page_icon="🤖", layout="wide")

# ----------------- AUTH ------------------
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())

def create_user(username: str, email: str, password: str) -> Tuple[bool, str]:
    try:
        user_id = str(uuid.uuid4())
        hashed_pw = hash_password(password)
        session.sql(f"""
            INSERT INTO CORTEX_ANALYST.CORTEX_AI.USER_CREDENTIALS
            (USER_ID, USERNAME, EMAIL, PASSWORD_HASH)
            VALUES ('{user_id}', '{username}', '{email}', '{hashed_pw}')
        """).collect()
        return True, "Account created successfully."
    except Exception as e:
        return False, f"Error creating user: {str(e)}"

def authenticate_user(username: str, password: str) -> Tuple[bool, str]:
    try:
        result = session.sql(f"""
            SELECT PASSWORD_HASH FROM CORTEX_ANALYST.CORTEX_AI.USER_CREDENTIALS
            WHERE USERNAME = '{username}'
        """).to_pandas()

        if not result.empty:
            hashed = result.iloc[0]['PASSWORD_HASH']
            if verify_password(password, hashed):
                session.sql(f"""
                    UPDATE CORTEX_ANALYST.CORTEX_AI.USER_CREDENTIALS
                    SET LAST_LOGIN = CURRENT_TIMESTAMP
                    WHERE USERNAME = '{username}'
                """).collect()
                return True, "Login successful."
            else:
                return False, "Incorrect password."
        else:
            return False, "Username not found."
    except Exception as e:
        return False, f"Error: {str(e)}"

def login_signup_interface():
    st.markdown("""
        <style>
        .login-box {
            background-color: #f9f9f9;
            padding: 2rem;
            border-radius: 10px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
            max-width: 400px;
            margin: 5rem auto;
        }
        </style>
    """, unsafe_allow_html=True)

    st.markdown("<div class='login-box'>", unsafe_allow_html=True)
    st.title("🔐 Cortex Analyst Portal")
    mode = st.selectbox("Select Action", ["Login", "Sign Up"])

    username = st.text_input("Username")
    email = st.text_input("Email", disabled=(mode == "Login"))
    password = st.text_input("Password", type="password")

    if st.button("Submit", use_container_width=True):
        with st.spinner("Processing..."):
            if mode == "Sign Up":
                success, msg = create_user(username, email, password)
                st.success(msg) if success else st.error(msg)
            else:
                success, msg = authenticate_user(username, password)
                if success:
                    st.session_state.logged_in = True
                    st.session_state.username = username
                    st.success(msg)
                    st.experimental_rerun()
                else:
                    st.error(msg)

    st.markdown("</div>", unsafe_allow_html=True)
    st.stop()

# ---------------- INIT STATE ------------------
def initialize_session_state():
    keys_defaults = {
        "messages": [], "user_messages": [], "active_suggestion": None,
        "message_counter": 0, "data_sources_info": {}, "chat_initialized": False,
        "processing": False, "pending_question": None
    }
    for k, v in keys_defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v

# ---------------- ANALYSIS ------------------
def call_cortex_analyst_procedure(user_message: str) -> Tuple[Optional[Dict], Optional[str]]:
    try:
        messages_list = [{"role": "user", "content": [{"type": "text", "text": user_message}]}]
        messages_json = json.dumps(messages_list)
        result = session.call(CHAT_PROCEDURE, messages_json, SEMANTIC_MODEL_PATH)
        if not result:
            return None, "No response from procedure"
        response = json.loads(result)
        if response.get("success", False):
            return response.get("content", {}), None
        return None, response.get("error_message", "Unknown procedure error")
    except Exception as e:
        return None, f"Error: {str(e)}"

def call_dremio_data_procedure(sql: str) -> Tuple[Optional[pd.DataFrame], Optional[str]]:
    try:
        result = session.call(DREMIO_PROCEDURE, sql)
        return (result.to_pandas() if hasattr(result, "to_pandas") else result), None
    except Exception as e:
        return None, f"Dremio Error: {str(e)}"

# ---------------- UI UTILS ------------------
def timed_spinner():
    with st.spinner("🤔 Please wait, analyzing your question..."):
        start = time.time()
        while True:
            elapsed = time.time() - start
            if elapsed > 15:
                st.toast("⌛ It's almost done. Please hold on...", icon='🔄')
                break
            elif elapsed > 5:
                st.toast("📡 Hold on, it's taking longer than expected...", icon='⚠️')
            time.sleep(1)
            if elapsed > 20:
                break

# ---------------- CHAT ------------------
def process_user_question(question: str):
    st.session_state.processing = True
    st.session_state.messages.append({"role": "user", "content": question, "timestamp": datetime.now()})
    with st.chat_message("user"):
        st.markdown(question)
    timed_spinner()
    response_content, error = call_cortex_analyst_procedure(question)
    if error:
        st.error(f"❌ {error}")
        return
    with st.chat_message("assistant"):
        text = extract_text_from_response(response_content)
        if text:
            st.markdown(text)
        sql = extract_sql_from_response(response_content)
        if sql:
            with st.spinner("🔄 Executing SQL and generating visualization..."):
                df, sql_err = call_dremio_data_procedure(sql)
                if df is not None:
                    sources = identify_data_sources_from_sql(sql)
                    create_visualization_with_tabs(df, sql, sources)
                elif sql_err:
                    st.error(sql_err)
        suggestions = extract_suggestions_from_response(response_content)
        if suggestions:
            display_suggestions(suggestions)
    st.session_state.messages.append({"role": "assistant", "content": response_content, "timestamp": datetime.now()})
    time.sleep(0.5)
    st.experimental_rerun()

# ---------------- RESPONSE EXTRACTORS ------------------
def extract_sql_from_response(content: Dict) -> Optional[str]:
    for block in content.get("message", {}).get("content", []):
        if block.get("type") == "sql":
            return block.get("statement", "")
    return None

def extract_suggestions_from_response(content: Dict) -> List[str]:
    for block in content.get("message", {}).get("content", []):
        if block.get("type") == "suggestions":
            return block.get("suggestions", [])
    return []

def extract_text_from_response(content: Dict) -> str:
    return "\n".join([block.get("text", "") for block in content.get("message", {}).get("content", []) if block.get("type") == "text"])

# ---------------- VISUALIZATION ------------------
def identify_data_sources_from_sql(sql: str) -> List[str]:
    sources = []
    mapping = { 'salesforce': '🔹 Salesforce', 'odoo': '🟦 Odoo', 'sap': '🟨 SAP', 'dremio': '🔷 Dremio', 'warehouse': '🏢 Data Warehouse' }
    for k, v in mapping.items():
        if k in sql.lower():
            sources.append(v)
    return sources or ['🏢 Data Warehouse']

def display_charts_tab(df: pd.DataFrame, key_suffix: str):
    if len(df.columns) >= 2:
        cols = list(df.columns)
        col1, col2 = st.columns(2)
        x_col = col1.selectbox("X axis", cols, key=f"x_{key_suffix}")
        y_col = col2.selectbox("Y axis", [c for c in cols if c != x_col], key=f"y_{key_suffix}")
        chart_type = st.selectbox("Chart type", ["Line", "Bar", "Pie", "Scatter"], key=f"type_{key_suffix}")
        data = df[[x_col, y_col]].dropna()
        if chart_type == "Line": st.line_chart(data.set_index(x_col))
        elif chart_type == "Bar": st.bar_chart(data.set_index(x_col))
        elif chart_type == "Pie":
            pie = alt.Chart(data).mark_arc().encode(
                theta=alt.Theta(field=y_col, type="quantitative"),
                color=alt.Color(field=x_col, type="nominal")
            )
            st.altair_chart(pie, use_container_width=True)
        elif chart_type == "Scatter":
            sc = alt.Chart(data).mark_circle().encode(x=x_col, y=y_col)
            st.altair_chart(sc, use_container_width=True)
    else:
        st.warning("Not enough columns to visualize.")

def create_visualization_with_tabs(df: pd.DataFrame, sql: str, sources: List[str]):
    st.info("Data Sources: " + " • ".join(sources))
    tab1, tab2 = st.tabs(["Data Table", "Charts"])
    with tab1:
        st.dataframe(df, use_container_width=True)
    with tab2:
        sql_key = hashlib.md5(sql.encode()).hexdigest()[:6]
        display_charts_tab(df, sql_key)

def display_suggestions(suggestions: List[str]):
    if suggestions:
        st.markdown("💡 Suggested follow-up questions:")
        cols = st.columns(2)
        for i, s in enumerate(suggestions):
            if cols[i % 2].button(s, key=f"sugg_{i}"):
                st.session_state.pending_question = s
                st.experimental_rerun()

# ---------------- CHAT RENDER ------------------
def render_chat_interface():
    st.title("🤖 NLP Chat with Data")
    for msg in st.session_state.messages:
        with st.chat_message(msg["role"]):
            if msg["role"] == "user":
                st.markdown(msg["content"])
            else:
                text = extract_text_from_response(msg["content"])
                st.markdown(text)
                sql = extract_sql_from_response(msg["content"])
                if sql:
                    df, err = call_dremio_data_procedure(sql)
                    if df is not None:
                        sources = identify_data_sources_from_sql(sql)
                        create_visualization_with_tabs(df, sql, sources)
                sug = extract_suggestions_from_response(msg["content"])
                if sug:
                    display_suggestions(sug)
    question = st.chat_input("Ask me anything about your data")
    if question:
        st.session_state.pending_question = question
        st.experimental_rerun()

# ---------------- MAIN ------------------
def main():
    if not st.session_state.get("logged_in"):
        login_signup_interface()
    initialize_session_state()
    if not st.session_state.chat_initialized:
        _, _ = call_cortex_analyst_procedure("Help me get started")
        st.session_state.chat_initialized = True
    if st.session_state.pending_question:
        q = st.session_state.pending_question
        st.session_state.pending_question = None
        process_user_question(q)
    render_chat_interface()

if __name__ == "__main__":
    main()
