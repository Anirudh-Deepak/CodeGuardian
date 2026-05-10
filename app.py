import streamlit as st
import os
import json
import zipfile
import pandas as pd
import plotly.express as px
import time
import hashlib
import shutil

from scanner import scan_directory, scan_file
from analyzer import analyze_findings
from ai_advisor import get_ai_advice

st.set_page_config(page_title="CodeGuardian AI", layout="wide")

USER_FILE = "users.json"

def hash_password(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

def mask_secret(value):
    if not value:
        return "****"

    value = str(value)

    if len(value) <= 4:
        return "*" * len(value)

    start = value[:2]
    end = value[-2:]

    masked_middle = "*" * (len(value) - 4)

    return start + masked_middle + end

def load_users():
    if os.path.exists(USER_FILE):
        with open(USER_FILE, "r") as f:
            return json.load(f)
    return {}

def save_users(users):
    with open(USER_FILE, "w") as f:
        json.dump(users, f)

SEVERITY_SCORE = {
    "CRITICAL": 10,
    "HIGH": 8,
    "MEDIUM": 5,
    "LOW": 3
}

def fallback_advice(secret_type):
    return (
        "Sensitive data detected which may expose systems if leaked. Such values should not be stored in code.",
        "Use environment variables or secret management systems and avoid committing secrets to source files."
    )

if "users" not in st.session_state:
    st.session_state.users = load_users()

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

if "current_user" not in st.session_state:
    st.session_state.current_user = ""

if "results" not in st.session_state:
    st.session_state.results = None

def auth_page():
    st.markdown("<h1 style='text-align:center;'>CodeGuardian AI</h1>", unsafe_allow_html=True)
    st.markdown("<p style='text-align:center; color:gray;'>Secure • Detect • Analyze Your Code</p>", unsafe_allow_html=True)

    choice = st.radio("Select", ["Login", "Sign Up"])
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if choice == "Sign Up":
        if st.button("Create Account"):
            if username in st.session_state.users:
                st.error("User already exists")
            else:
                st.session_state.users[username] = hash_password(password)
                save_users(st.session_state.users)
                st.success("Account created")

    else:
        if st.button("Login"):
            if username in st.session_state.users and st.session_state.users[username] == hash_password(password):
                st.session_state.logged_in = True
                st.session_state.current_user = username
                st.rerun()
            else:
                st.error("Invalid credentials")

def upload_page():

    st.markdown("<h1 style='text-align:center;'>CodeGuardian AI</h1>", unsafe_allow_html=True)
    st.markdown("<p style='text-align:center; color:gray;'>Secure • Detect • Analyze Your Code</p>", unsafe_allow_html=True)

    st.markdown("### 📤 Upload Your Project")

    uploaded_file = st.file_uploader(
        "Upload file or ZIP project",
        type=["zip", "py", "js", "java", "c", "cpp", "json"]
    )

    if uploaded_file:

        extract_path = "uploaded_project"

        if os.path.exists(extract_path):
            shutil.rmtree(extract_path)

        os.makedirs(extract_path, exist_ok=True)

        file_path = os.path.join(extract_path, uploaded_file.name)

        with open(file_path, "wb") as f:
            f.write(uploaded_file.getbuffer())

        if uploaded_file.name.endswith(".zip"):

            try:
                with zipfile.ZipFile(file_path, "r") as zip_ref:
                    zip_ref.extractall(extract_path)

                st.success("ZIP extracted successfully")

            except Exception as e:
                st.error(f"ZIP extraction failed: {e}")
                return

        if st.button("🚀 Run Scan"):

            try:

                if uploaded_file.name.endswith(".zip"):
                    findings = scan_directory(extract_path)
                else:
                    findings = scan_file(file_path)

                analyzed = analyze_findings(findings)
                if len(analyzed) == 0:
                    st.warning("No secrets detected")
                    return

                progress = st.progress(0)

                cached_advice = {}

                for i, item in enumerate(analyzed):

                    try:

                        if item["type"] in cached_advice:

                            danger, fix = cached_advice[item["type"]]

                        else:

                            advice = get_ai_advice(
                                item["type"],
                                item["code"]
                            )

                            if advice and isinstance(advice, str):

                                if (
                                    "Fix:" in advice
                                    and
                                    "Why Dangerous:" in advice
                                ):

                                    parts = advice.split("Fix:")

                                    danger = parts[0].replace(
                                        "Why Dangerous:",
                                        ""
                                    ).strip()

                                    fix = parts[1].strip()

                                else:

                                    danger, fix = fallback_advice(
                                        item["type"]
                                    )

                            else:

                                danger, fix = fallback_advice(
                                    item["type"]
                                )

                            cached_advice[item["type"]] = (
                                danger,
                                fix
                            )

                    except Exception:

                        danger, fix = fallback_advice(
                            item["type"]
                        )

                    item["danger"] = danger
                    item["fix"] = fix

                    item["score"] = SEVERITY_SCORE.get(
                        item["severity"],
                        1
                    )

                    progress.progress(
                        (i + 1) / len(analyzed)
                    )

                    time.sleep(0.02)
                st.session_state.results = analyzed

                st.success("✅ Scan Completed!")

            except Exception as e:
                st.error(f"Scan failed: {e}")
                
def analysis_page():
    st.header("📊 Analysis")

    if st.session_state.results is None:
        st.warning("Run a scan first")
        return

    df = pd.DataFrame(st.session_state.results)
    if df.empty:
        st.warning("No findings available")
        return
    df = df.sort_values(by="score", ascending=False)

    file_scores = df.groupby("file")["score"].sum().sort_values(ascending=False)
    if not file_scores.empty:
        st.error(f"🚨 Most Vulnerable File: {file_scores.index[0]}")

    critical = len(df[df["severity"] == "CRITICAL"])
    high = len(df[df["severity"] == "HIGH"])

    st.subheader("🔍 Security Findings Summary")

    if critical > 0:
        st.error(f"⚠️ {critical} Critical issue(s) require immediate attention")
    elif high > 0:
        st.warning(f"⚠️ {high} High severity issue(s) detected")
    else:
        st.success("✅ No critical issues found")

    col1, col2, col3, col4, col5 = st.columns(5)

    col1.metric("Total", len(df))
    col2.metric("Critical", critical)
    col3.metric("High", high)
    col4.metric("Medium", len(df[df["severity"] == "MEDIUM"]))
    col5.metric("Low", len(df[df["severity"] == "LOW"]))

    st.divider()

    for item in df.to_dict("records"):
        st.subheader(f"{item['file']} (Line {item['line']})")

        masked_value = mask_secret(item.get("value", ""))
        st.code(f"{item['type']} = {masked_value}")

        st.write(f"Severity: {item['severity']} | Score: {item['score']}")
        st.write(f"Occurrences: {item.get('occurrences',1)}")

        st.write("Why Dangerous:")
        st.write(item["danger"])

        st.write("Fix:")
        st.write(item["fix"])

        st.divider()

    csv = df.to_csv(index=False)
    st.download_button("📥 Download Report", data=csv, file_name="report.csv")

def visualization_page():
    st.header("📈 Visualization")

    if st.session_state.results is None:
        st.warning("Run scan first")
        return

    df = pd.DataFrame(st.session_state.results)
    if df.empty:
        st.warning("No data available for visualization")
        return

    col1, col2 = st.columns(2)
    col1.plotly_chart(px.pie(df, names="severity"), use_container_width=True)
    col2.plotly_chart(px.bar(df, x="type"), use_container_width=True)

if not st.session_state.logged_in:
    auth_page()
else:
    st.sidebar.write(f"👤 {st.session_state.current_user}")

    page = st.sidebar.radio("Navigation", ["Upload & Scan","Analysis","Visualization","Logout"])

    if page == "Upload & Scan":
        upload_page()
    elif page == "Analysis":
        analysis_page()
    elif page == "Visualization":
        visualization_page()
    elif page == "Logout":
        st.session_state.logged_in = False
        st.session_state.current_user = ""
        st.session_state.results = None
        st.rerun()