import json
import streamlit as st
import pandas as pd
from snowflake.snowpark.exceptions import SnowparkSQLException
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Union
import altair as alt
import numpy as np
import re
import hashlib
import uuid
import bcrypt

# get connections
cnx = st.connection("snowflake")
session = cnx.session()

# Configuration
SEMANTIC_MODEL_PATH = "CORTEX_ANALYST.CORTEX_AI.CORTEX_ANALYST_STAGE/nlp.yaml"
CHAT_PROCEDURE = "CORTEX_ANALYST.CORTEX_AI.CORTEX_ANALYST_CHAT_PROCEDURE1"
DREMIO_PROCEDURE = "SALESFORCE_DREMIO.SALESFORCE_SCHEMA_DREMIO.DREMIO_DATA_PROCEDURE"

# Page configuration
st.set_page_config(
    page_title="Cortex Analyst Chat",
    page_icon="🤖",
    layout="wide",
    initial_sidebar_state="collapsed"
)
def initialize_session_state():
    """Initialize session state variables for chat functionality."""
    if "messages" not in st.session_state:
        st.session_state.messages = []
    if "user_messages" not in st.session_state:
        st.session_state.user_messages = []
    if "active_suggestion" not in st.session_state:
        st.session_state.active_suggestion = None
    if "message_counter" not in st.session_state:
        st.session_state.message_counter = 0
    if "data_sources_info" not in st.session_state:
        st.session_state.data_sources_info = {}
    if "chat_initialized" not in st.session_state:
        st.session_state.chat_initialized = False
    if "processing" not in st.session_state:
        st.session_state.processing = False
    if "pending_question" not in st.session_state:
        st.session_state.pending_question = None

def call_cortex_analyst_procedure(user_message: str) -> Tuple[Optional[Dict], Optional[str]]:
    """Call the Cortex Analyst procedure with user message."""
    try:
        messages_list = [{
            "role": "user",
            "content": [{"type": "text", "text": user_message}]
        }]
        
        messages_json = json.dumps(messages_list)
        result = session.call(CHAT_PROCEDURE, messages_json, SEMANTIC_MODEL_PATH)
        
        if not result:
            return None, "No response from procedure"
        
        procedure_response = json.loads(result)
        
        if procedure_response.get("success", False):
            return procedure_response.get("content", {}), None
        else:
            return None, procedure_response.get("error_message", "Unknown procedure error")
            
    except SnowparkSQLException as e:
        return None, f"Database Error: {str(e)}"
    except json.JSONDecodeError as e:
        return None, f"Invalid JSON response: {str(e)}"
    except Exception as e:
        return None, f"Unexpected error: {str(e)}"

def call_dremio_data_procedure(sql_statement: str) -> Tuple[Optional[pd.DataFrame], Optional[str]]:
    """Execute SQL via Dremio procedure."""
    try:
        df_result = session.call(DREMIO_PROCEDURE, sql_statement)
        
        if hasattr(df_result, "to_pandas"):
            return df_result.to_pandas(), None
        elif isinstance(df_result, pd.DataFrame):
            return df_result, None
        else:
            return None, "Unexpected result format from Dremio procedure"
            
    except SnowparkSQLException as e:
        return None, f"Dremio SQL Error: {str(e)}"
    except Exception as e:
        return None, f"Dremio Error: {str(e)}"

def identify_data_sources_from_sql(sql_statement: str) -> List[str]:
    """Identify data sources from SQL statement."""
    sources = []
    sql_lower = sql_statement.lower()
    
    source_mapping = {
        'salesforce': '🔹 Salesforce',
        'odoo': '🟦 Odoo', 
        'sap': '🟨 SAP',
        'dremio': '🔷 Dremio',
        'warehouse': '🏢 Data Warehouse'
    }
    
    for keyword, display_name in source_mapping.items():
        if keyword in sql_lower:
            sources.append(display_name)
    
    # If no specific source found, try to infer from schema/table names
    if not sources:
        if any(term in sql_lower for term in ['account', 'opportunity', 'lead', 'contact']):
            sources.append('🔹 Salesforce')
        elif any(term in sql_lower for term in ['partner', 'product', 'stock']):
            sources.append('🟦 Odoo')
        else:
            sources.append('🏢 Data Warehouse')
    
    return sources

def display_charts_tab(df: pd.DataFrame, key_suffix: str) -> None:
    """
    Display various charts based on the DataFrame using unique keys.
    This logic is taken from the second code.
    """
    if len(df.columns) >= 2:
        all_cols = list(df.columns)

        col1, col2 = st.columns(2)
        x_col = col1.selectbox("X axis", all_cols, key=f"x_col_{key_suffix}")
        y_col = col2.selectbox(
            "Y axis", [col for col in all_cols if col != x_col], key=f"y_col_{key_suffix}"
        )

        chart_type = st.selectbox(
            "Select chart type",
            [
                "Line Chart 📈", "Bar Chart 📊", "Pie Chart 🥧", "Scatter Plot 🔵",
                "Histogram 📊", "Box Plot 📦", "Combo Chart 🔀", "Number Chart 🔢"
            ],
            key=f"chart_type_{key_suffix}"
        )

        chart_data = df[[x_col, y_col]].dropna()

        if chart_type == "Line Chart 📈":
            st.line_chart(chart_data.set_index(x_col))

        elif chart_type == "Bar Chart 📊":
            st.bar_chart(chart_data.set_index(x_col))

        elif chart_type == "Pie Chart 🥧":
            pie = alt.Chart(chart_data).mark_arc().encode(
                theta=alt.Theta(field=y_col, type="quantitative"),
                color=alt.Color(field=x_col, type="nominal")
            )
            st.altair_chart(pie, use_container_width=True)

        elif chart_type == "Scatter Plot 🔵":
            scatter = alt.Chart(chart_data).mark_circle(size=60).encode(
                x=x_col,
                y=y_col,
                tooltip=[x_col, y_col]
            ).interactive()
            st.altair_chart(scatter, use_container_width=True)

        elif chart_type == "Histogram 📊":
            hist = alt.Chart(chart_data).mark_bar().encode(
                alt.X(y_col, bin=True),
                y='count()'
            )
            st.altair_chart(hist, use_container_width=True)

        elif chart_type == "Box Plot 📦":
            box = alt.Chart(chart_data).mark_boxplot().encode(
                x=x_col,
                y=y_col
            )
            st.altair_chart(box, use_container_width=True)

        elif chart_type == "Combo Chart 🔀":
            line = alt.Chart(chart_data).mark_line(color='blue').encode(x=x_col, y=y_col)
            bar = alt.Chart(chart_data).mark_bar(opacity=0.3).encode(x=x_col, y=y_col)
            combo = bar + line
            st.altair_chart(combo, use_container_width=True)

        elif chart_type == "Number Chart 🔢":
            st.metric(label=f"{y_col} Total", value=round(chart_data[y_col].sum(), 2))

    else:
        st.warning("⚠️ At least 2 columns are required to render a chart.")

def create_visualization_with_tabs(df: pd.DataFrame, sql_statement: str, data_sources: List[str] = None) -> None:
    """Create visualization with data and chart tabs using logic from second code."""
    if df.empty:
        st.info("📊 No data to visualize.")
        return
    
    try:
        # Display data source information
        if data_sources:
            source_text = " • ".join(data_sources)
            st.info(f"📊 **Data Sources:** {source_text}")
        
        # Display SQL query
        # st.markdown("**Generated SQL:**")
        # st.code(sql_statement, language="sql")
        
        if not df.empty:
            # st.success("✅ Dremio executed successfully")
            tab1, tab2 = st.tabs(["Data 📄", "Chart 📉"])
            
            with tab1:
                st.dataframe(df, use_container_width=True)
                st.caption(f"📊 Showing {len(df)} rows × {len(df.columns)} columns")
            
            with tab2:
                # Use a stable hash from SQL statement as key
                sql_hash = hashlib.md5(sql_statement.encode()).hexdigest()[:8]
                display_charts_tab(df, sql_hash)
        else:
            st.warning("⚠️ No data returned from Dremio.")
            
    except Exception as e:
        st.error(f"Error creating visualization: {str(e)}")
        st.dataframe(df, use_container_width=True)

def extract_sql_from_response(response_content: Dict) -> Optional[str]:
    """Extract SQL statement from Cortex Analyst response."""
    try:
        message_content = response_content.get("message", {}).get("content", [])
        for block in message_content:
            if block.get("type") == "sql":
                return block.get("statement", "")
        return None
    except Exception:
        return None

def extract_suggestions_from_response(response_content: Dict) -> List[str]:
    """Extract suggestions from Cortex Analyst response."""
    try:
        message_content = response_content.get("message", {}).get("content", [])
        for block in message_content:
            if block.get("type") == "suggestions":
                return block.get("suggestions", [])
        return []
    except Exception:
        return []

def extract_text_from_response(response_content: Dict) -> str:
    """Extract text content from Cortex Analyst response."""
    try:
        message_content = response_content.get("message", {}).get("content", [])
        text_parts = []
        for block in message_content:
            if block.get("type") == "text":
                text_parts.append(block.get("text", ""))
        return "\n".join(text_parts)
    except Exception:
        return "Unable to extract response text."

def display_suggestions(suggestions: List[str], key_prefix: str = ""):
    """Display clickable suggestion buttons."""
    if not suggestions:
        return
    
    st.markdown("💡 **Suggested follow-up questions:**")
    
    # Create columns for suggestions (2 per row)
    cols = st.columns(2)
    for i, suggestion in enumerate(suggestions[:6]):  # Limit to 6 suggestions
        col_idx = i % 2
        with cols[col_idx]:
            if st.button(
                suggestion,
                key=f"{key_prefix}_suggestion_{i}",
                help="Click to ask this question",
                use_container_width=True
            ):
                st.session_state.active_suggestion = suggestion
                st.rerun()

def process_user_question(question: str):
    """Process user question and generate response."""
    try:
        st.session_state.processing = True
        
        # Add user message to chat
        st.session_state.messages.append({
            "role": "user",
            "content": question,
            "timestamp": datetime.now()
        })
        
        # Display user message
        with st.chat_message("user"):
            st.markdown(question)
        
        # Get AI response
        with st.spinner("🤔 Analyzing your question..."):
            response_content, error = call_cortex_analyst_procedure(question)
            
            if error:
                raise Exception(f"Cortex Analyst Error: {error}")
            
            if not response_content or not isinstance(response_content, dict):
                raise Exception("❌ Invalid or empty response from Cortex Analyst")
            
            # Display assistant response
            with st.chat_message("assistant"):
                # Display text response
                text_content = extract_text_from_response(response_content)
                if text_content:
                    st.markdown(text_content)
                
                # Extract and execute SQL if present
                sql_statement = extract_sql_from_response(response_content)
                if sql_statement:
                    # Execute SQL and create visualization
                    with st.spinner("🔄 Executing query and creating visualization..."):
                        df, sql_error = call_dremio_data_procedure(sql_statement)
                        
                        if df is not None:
                            # Identify data sources
                            data_sources = identify_data_sources_from_sql(sql_statement)
                            
                            # Create visualization with tabs
                            create_visualization_with_tabs(df, sql_statement, data_sources)
                            
                        elif sql_error:
                            st.error(f"❌ **SQL Execution Error:** {sql_error}")
                        else:
                            st.info("ℹ️ Query executed successfully but returned no data.")
                
                # Display suggestions
                suggestions = extract_suggestions_from_response(response_content)
                if suggestions:
                    display_suggestions(suggestions, f"msg_{len(st.session_state.messages)}")
            
            # Add assistant message to chat history
            st.session_state.messages.append({
                "role": "assistant",
                "content": response_content,
                "timestamp": datetime.now(),
                "message_id": f"msg_{len(st.session_state.messages)}"
            })
            
    except Exception as e:
        error_message = f"❌ Error: {str(e)}"
        st.error(error_message)
        
        # Add error message to chat history
        st.session_state.messages.append({
            "role": "assistant",
            "content": {"message": {"content": [{"type": "text", "text": error_message}]}},
            "timestamp": datetime.now(),
            "message_id": f"error_{len(st.session_state.messages)}"
        })
        
    finally:
        st.session_state.processing = False

def send_welcome_message():
    """Send welcome message to get initial suggestions."""
    if not st.session_state.chat_initialized:
        welcome_query = "What questions can I ask? Help me get started."
        response_content, error = call_cortex_analyst_procedure(welcome_query)
        
        if response_content and not error:
            # Store welcome message
            st.session_state.messages.append({
                "role": "assistant",
                "content": response_content,
                "timestamp": datetime.now(),
                "message_id": "welcome"
            })
        
        st.session_state.chat_initialized = True

def render_chat_interface():
    """Render the main chat interface."""
    # Handle pending question first
    if st.session_state.get("pending_question"):
        question = st.session_state.pending_question
        st.session_state.pending_question = None
        process_user_question(question)
        st.rerun()
    
    # Handle active suggestion
    if st.session_state.active_suggestion:
        question = st.session_state.active_suggestion
        st.session_state.active_suggestion = None
        st.session_state.pending_question = question
        st.rerun()
    
    # App header
    st.title("🤖 NLP-Based Dashboard's with Data")
    st.markdown("Let's get started, Ask questions about your data in natural language!")
    
    # Display existing chat messages (except the current processing one)
    for i, message in enumerate(st.session_state.messages):
        message_id = message.get("message_id", f"msg_{i}")
        
        if message["role"] == "user":
            with st.chat_message("user"):
                st.markdown(message["content"])
                
        elif message["role"] == "assistant":
            with st.chat_message("assistant"):
                response_content = message["content"]
                
                # Display text response
                text_content = extract_text_from_response(response_content)
                if text_content:
                    st.markdown(text_content)
                
                # Extract and show SQL + visualization if present
                sql_statement = extract_sql_from_response(response_content)
                if sql_statement:
                    # Re-execute query for historical messages (cached in real implementation)
                    df, sql_error = call_dremio_data_procedure(sql_statement)
                    
                    if df is not None and not df.empty:
                        data_sources = identify_data_sources_from_sql(sql_statement)
                        create_visualization_with_tabs(df, sql_statement, data_sources)
                    elif sql_error:
                        st.error(f"❌ **SQL Execution Error:** {sql_error}")
                
                # Display suggestions
                suggestions = extract_suggestions_from_response(response_content)
                if suggestions:
                    display_suggestions(suggestions, f"msg_{i}")
    
    # Chat input
    question = st.chat_input("Ask me anything about your data...", disabled=st.session_state.processing)
    if question:
        st.session_state.pending_question = question
        st.rerun()


# Helper to hash password
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

# Helper to verify password
def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())

# Create user account
def create_user(username: str, email: str, password: str) -> Tuple[bool, str]:
    try:
        user_id = str(uuid.uuid4())
        hashed_pw = hash_password(password)
        session.sql(f"""
            INSERT INTO CORTEX_ANALYST.CORTEX_AI.USER_CREDENTIALS
            (USER_ID, USERNAME, EMAIL, PASSWORD_HASH)
            VALUES ('{user_id}', '{username}', '{email}', '{hashed_pw}')
        """).collect()
        return True, "✅ Account created successfully."
    except Exception as e:
        return False, f"❌ Error creating user: {str(e)}"

# Authenticate user
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
                return True, "✅ Login successful."
            else:
                return False, "❌ Incorrect password."
        else:
            return False, "❌ Username not found."
    except Exception as e:
        return False, f"❌ Error: {str(e)}"

def login_signup_interface():
    st.title("🔐 Secure Login to Cortex Analyst")
    mode = st.radio("Select Mode", ["Login", "Sign Up"], horizontal=True)

    username = st.text_input("Username")
    email = st.text_input("Email (Sign Up only)", disabled=(mode == "Login"))
    password = st.text_input("Password", type="password")

    if st.button("Submit"):
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

    st.stop()

def main():
    if not st.session_state.get("logged_in"):
        login_signup_interface()
        
    initialize_session_state()
    send_welcome_message()
    render_chat_interface()

if __name__ == "__main__":
    main()
