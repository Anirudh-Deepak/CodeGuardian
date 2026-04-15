import streamlit as st
import os
import json
import zipfile
import pandas as pd
import plotly.express as px
import time

from scanner import scan_directory, scan_file
from analyzer import analyze_findings
from ai_advisor import get_ai_advice

st.set_page_config(page_title="CodeGuardian AI", layout="wide")

USER_FILE = "users.json"

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
    data = {
        "API Key": (
            "API keys in code can be exposed and misused to access services or consume resources.",
            "Store keys securely using environment variables and avoid committing them."
        ),
        "Password": (
            "Hardcoded passwords can be discovered and lead to unauthorized access.",
            "Use secure credential storage instead of embedding passwords in code."
        ),
        "Access Token": (
            "Exposed tokens allow attackers to act as authenticated users.",
            "Store tokens securely and rotate them periodically."
        ),
        "AWS Access Key": (
            "AWS keys provide direct cloud access and can cause serious damage.",
            "Use IAM roles and avoid embedding keys in applications."
        ),
        "Private Key": (
            "Private keys are critical for encryption and must remain confidential.",
            "Use secure key management systems and never expose them."
        ),
        "Database URL": (
            "Database URLs may contain credentials exposing sensitive data.",
            "Move credentials to environment variables."
        ),
        "JWT Token": (
            "JWT tokens can be used to hijack sessions if exposed.",
            "Generate tokens dynamically and store them securely."
        )
    }
    return data.get(secret_type, ("Sensitive data risk.", "Secure this value properly."))

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
                st.session_state.users[username] = password
                save_users(st.session_state.users)
                st.success("Account created")

    else:
        if st.button("Login"):
            if username in st.session_state.users and st.session_state.users[username] == password:
                st.session_state.logged_in = True
                st.session_state.current_user = username
                st.rerun()
            else:
                st.error("Invalid credentials")

def upload_page():
    st.markdown("<h1 style='text-align:center;'>CodeGuardian AI</h1>", unsafe_allow_html=True)
    st.markdown("<p style='text-align:center; color:gray;'>Secure • Detect • Analyze Your Code</p>", unsafe_allow_html=True)

    st.write("")
    st.markdown("### 📤 Upload Your Project")

    uploaded_file = st.file_uploader("Upload file or ZIP project", type=["zip","py","js","java","c","cpp"])

    if uploaded_file:
        extract_path = "uploaded_project"
        os.makedirs(extract_path, exist_ok=True)

        file_path = os.path.join(extract_path, uploaded_file.name)

        with open(file_path, "wb") as f:
            f.write(uploaded_file.getbuffer())

        if uploaded_file.name.endswith(".zip"):
            with zipfile.ZipFile(file_path, "r") as zip_ref:
                zip_ref.extractall(extract_path)

        if st.button("🚀 Run Scan"):
            findings = scan_directory(extract_path) if uploaded_file.name.endswith(".zip") else scan_file(file_path)
            analyzed = analyze_findings(findings)

            progress = st.progress(0)

            for i, item in enumerate(analyzed):
                try:
                    advice = get_ai_advice(item["type"], item["code"])

                    if (
                        not advice or
                        "429" in str(advice) or
                        "Rate limit" in str(advice) or
                        "Error" in str(advice)
                    ):
                        danger, fix = fallback_advice(item["type"])
                    else:
                        if "Fix:" in advice:
                            parts = advice.split("Fix:")
                            danger = parts[0].replace("Why Dangerous:", "").strip()
                            fix = parts[1].strip()
                        else:
                            danger, fix = fallback_advice(item["type"])

                except:
                    danger, fix = fallback_advice(item["type"])

                item["danger"] = danger
                item["fix"] = fix
                item["score"] = SEVERITY_SCORE.get(item["severity"], 1)

                progress.progress((i + 1) / len(analyzed))
                time.sleep(0.2)

            st.session_state.results = analyzed

            st.markdown("""
            <div style="text-align:center; padding:20px; border-radius:10px; background-color:#f3f4f6;">
                <h4>✅ Scan Completed Successfully</h4>
                <p>
                👉 Go to <b>Analysis</b> to view detailed findings<br>
                👉 Go to <b>Visualization</b> for graphical insights
                </p>
            </div>
            """, unsafe_allow_html=True)

def analysis_page():
    st.header("📊 Analysis")

    if st.session_state.results is None:
        st.warning("Run a scan first")
        return

    df = pd.DataFrame(st.session_state.results)

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Issues", len(df))
    col2.metric("Critical", len(df[df["severity"] == "CRITICAL"]))
    col3.metric("High", len(df[df["severity"] == "HIGH"]))
    col4.metric("Medium", len(df[df["severity"] == "MEDIUM"]))

    st.divider()

    for item in st.session_state.results:
        st.subheader(f"{item['file']} (Line {item['line']})")

        col1, col2 = st.columns([3,1])
        col1.code(item["code"])
        col2.write(f"**Severity:** {item['severity']}")
        col2.write(f"**Score:** {item['score']}/10")

        st.write("**Why Dangerous:**")
        st.write(item["danger"])

        st.write("**Fix:**")
        st.write(item["fix"])

        st.divider()

def visualization_page():
    st.header("📈 Visualization")

    if st.session_state.results is None:
        st.warning("Run a scan first")
        return

    df = pd.DataFrame(st.session_state.results)

    col1, col2 = st.columns(2)
    col1.plotly_chart(px.pie(df, names="severity", hole=0.5), use_container_width=True)
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