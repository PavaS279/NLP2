import json
import streamlit as st
import pandas as pd
import altair as alt
import hashlib
from typing import Dict, List, Optional

# Streamlit Cloud-compatible Snowflake connection
cnx = st.connection("snowflake")
session = cnx.session()

# Configuration
SEMANTIC_MODEL_PATH = "CORTEX_ANALYST.CORTEX_AI.CORTEX_ANALYST_STAGE/nlp.yaml"
CHAT_PROCEDURE = "CORTEX_ANALYST.CORTEX_AI.CORTEX_ANALYST_CHAT_PROCEDURE"
DREMIO_PROCEDURE = "SALESFORCE_DREMIO.SALESFORCE_SCHEMA_DREMIO.DREMIO_DATA_PROCEDURE"
FEEDBACK_PROCEDURE = "CORTEX_ANALYST.CORTEX_AI.SUBMIT_FEEDBACK_PROCEDURE"

def initialize_session():
    if "messages" not in st.session_state:
        st.session_state.messages = []
    if "display_messages" not in st.session_state:
        st.session_state.display_messages = []
    if "processing" not in st.session_state:
        st.session_state.processing = False
    if "pending_question" not in st.session_state:
        st.session_state.pending_question = None

def call_analyst_procedure(messages: List[Dict]) -> (Dict, Optional[str]):
    try:
        messages_json = json.dumps(messages)
        result = session.call(CHAT_PROCEDURE, messages_json, SEMANTIC_MODEL_PATH)
        parsed = json.loads(result)
        if parsed.get("success"):
            return parsed, None
        return {}, parsed.get("error_message", "Unknown error")
    except Exception as e:
        return {}, str(e)

def call_dremio_data_procedure(sql: str):
    try:
        df_result = session.call(DREMIO_PROCEDURE, sql)
        if hasattr(df_result, "to_pandas"):
            return df_result.to_pandas(), None
        return None, "Unexpected result format from Dremio procedure"
    except Exception as e:
        return None, f"Dremio Error: {str(e)}"

def submit_feedback_procedure(request_id: str, positive: bool, message: str) -> Optional[str]:
    try:
        result = session.call(FEEDBACK_PROCEDURE, request_id, positive, message)
        return None if result == "Success" else result
    except Exception as e:
        return str(e)

def display_chat_message(role: str, content: dict):
    with st.chat_message(role):
        if content.get("type") == "text":
            st.markdown(content.get("value"))
        elif content.get("type") == "sql":
            st.code(content.get("value"), language="sql")
        elif content.get("type") == "result":
            df = pd.DataFrame(content.get("data"))
            sql = content.get("sql")
            st.markdown("**Generated SQL:**")
            st.code(sql, language="sql")
            if not df.empty:
                st.success("✅ Dremio executed successfully")
                tab1, tab2 = st.tabs(["Data 📄", "Chart 📉"])
                with tab1:
                    st.dataframe(df, use_container_width=True)
                with tab2:
                    sql_hash = hashlib.md5(sql.encode()).hexdigest()[:8]
                    display_charts_tab(df, sql_hash)
            else:
                st.warning("⚠️ No data returned from Dremio.")

def display_charts_tab(df: pd.DataFrame, key_suffix: str):
    if len(df.columns) >= 2:
        all_cols = list(df.columns)
        col1, col2 = st.columns(2)
        x_col = col1.selectbox("X axis", all_cols, key=f"x_{key_suffix}")
        y_col = col2.selectbox("Y axis", [c for c in all_cols if c != x_col], key=f"y_{key_suffix}")
        chart_type = st.selectbox(
            "Select chart type",
            [
                "Line Chart 📈", "Bar Chart 📊", "Pie Chart 🥧", "Scatter Plot 🔵",
                "Histogram 📊", "Box Plot 📦", "Combo Chart 🔀", "Number Chart 🔢"
            ],
            key=f"type_{key_suffix}"
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
                x=x_col, y=y_col, tooltip=[x_col, y_col]
            ).interactive()
            st.altair_chart(scatter, use_container_width=True)
        elif chart_type == "Histogram 📊":
            hist = alt.Chart(chart_data).mark_bar().encode(
                alt.X(y_col, bin=True), y='count()'
            )
            st.altair_chart(hist, use_container_width=True)
        elif chart_type == "Box Plot 📦":
            box = alt.Chart(chart_data).mark_boxplot().encode(x=x_col, y=y_col)
            st.altair_chart(box, use_container_width=True)
        elif chart_type == "Combo Chart 🔀":
            line = alt.Chart(chart_data).mark_line(color='blue').encode(x=x_col, y=y_col)
            bar = alt.Chart(chart_data).mark_bar(opacity=0.3).encode(x=x_col, y=y_col)
            st.altair_chart(bar + line, use_container_width=True)
        elif chart_type == "Number Chart 🔢":
            st.metric(label=f"{y_col} Total", value=round(chart_data[y_col].sum(), 2))
    else:
        st.warning("⚠️ Need at least 2 columns to plot chart.")

def process_user_question(question):
    try:
        st.session_state.processing = True
        st.session_state.messages.append({
            "role": "user",
            "content": [{"type": "text", "text": question}]
        })
        st.session_state.display_messages.append({
            "role": "user",
            "content": {"type": "text", "value": question}
        })
        response, error = call_analyst_procedure(st.session_state.messages)
        if error:
            raise Exception(error)
        analyst_response = response.get("message", {})
        content_block = analyst_response.get("content", [])
        sql_statement, explanation = "", ""
        for block in content_block:
            if block.get("type") == "text":
                explanation = block.get("text", "")
            elif block.get("type") == "sql":
                sql_statement = block.get("statement", "")
        if not sql_statement:
            raise Exception("No SQL generated.")
        dremio_result, dremio_error = call_dremio_data_procedure(sql_statement)
        if dremio_error:
            raise Exception(dremio_error)
        st.session_state.messages.append({"role": "analyst", "content": content_block})
        st.session_state.display_messages.append({
            "role": "assistant",
            "content": {
                "type": "result",
                "sql": sql_statement,
                "data": dremio_result.to_dict(orient="records")
            }
        })
    except Exception as e:
        st.error(f"❌ Error: {str(e)}")
        st.session_state.display_messages.append({
            "role": "assistant",
            "content": {"type": "text", "value": f"❌ Error: {str(e)}"}
        })
    finally:
        st.session_state.processing = False

def render_chat_interface():
    if st.session_state.get("pending_question"):
        q = st.session_state.pending_question
        st.session_state.pending_question = None
        process_user_question(q)
        st.rerun()

    st.title("🧠 NLP Bashboards with Unified ERP Data")
    st.caption("Ask natural language questions. Get SQL + Visual Data insights.")

    for msg in st.session_state.display_messages:
        display_chat_message(msg["role"], msg["content"])

    prompt = st.chat_input("Ask something...", disabled=st.session_state.processing)
    if prompt:
        st.session_state.pending_question = prompt
        st.rerun()

# Entry point
initialize_session()
render_chat_interface()
