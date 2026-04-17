import streamlit as st
import os
import json
import zipfile
import pandas as pd
import plotly.express as px
import time
import hashlib  # ⭐ NEW

from scanner import scan_directory, scan_file
from analyzer import analyze_findings
from ai_advisor import get_ai_advice

st.set_page_config(page_title="CodeGuardian AI", layout="wide")

USER_FILE = "users.json"

# ⭐ NEW - hashing
def hash_password(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

# ⭐ NEW - masking
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

# 🔥 fallback unchanged
def fallback_advice(secret_type):
    return (
        "Sensitive data detected which may expose systems if leaked. Such values should not be stored in code.",
        "Use environment variables or secret management systems and avoid committing secrets to source files."
    )

# ---------------- SESSION ----------------
if "users" not in st.session_state:
    st.session_state.users = load_users()

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

if "current_user" not in st.session_state:
    st.session_state.current_user = ""

if "results" not in st.session_state:
    st.session_state.results = None

# ---------------- AUTH ----------------
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
                # ⭐ HASHED
                st.session_state.users[username] = hash_password(password)
                save_users(st.session_state.users)
                st.success("Account created")

    else:
        if st.button("Login"):
            # ⭐ HASH CHECK
            if username in st.session_state.users and st.session_state.users[username] == hash_password(password):
                st.session_state.logged_in = True
                st.session_state.current_user = username
                st.rerun()
            else:
                st.error("Invalid credentials")

# ---------------- UPLOAD ----------------
def upload_page():
    st.markdown("<h1 style='text-align:center;'>CodeGuardian AI</h1>", unsafe_allow_html=True)
    st.markdown("<p style='text-align:center; color:gray;'>Secure • Detect • Analyze Your Code</p>", unsafe_allow_html=True)

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

                    if advice and isinstance(advice, str):
                        if "Fix:" in advice and "Why Dangerous:" in advice:
                            parts = advice.split("Fix:")
                            danger = parts[0].replace("Why Dangerous:", "").strip()
                            fix = parts[1].strip()
                        else:
                            danger, fix = fallback_advice(item["type"])
                    else:
                        danger, fix = fallback_advice(item["type"])

                except:
                    danger, fix = fallback_advice(item["type"])

                item["danger"] = danger
                item["fix"] = fix
                item["score"] = SEVERITY_SCORE.get(item["severity"], 1)

                progress.progress((i + 1) / len(analyzed))
                time.sleep(0.05)

            st.session_state.results = analyzed
            st.success("✅ Scan Completed!")

# ---------------- ANALYSIS ----------------
def analysis_page():
    st.header("📊 Analysis")

    if st.session_state.results is None:
        st.warning("Run a scan first")
        return

    df = pd.DataFrame(st.session_state.results)
    df = df.sort_values(by="score", ascending=False)

    # ⭐ NEW - most dangerous file
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

        # ⭐ MASKED OUTPUT
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

# ---------------- VISUAL ----------------
def visualization_page():
    st.header("📈 Visualization")

    if st.session_state.results is None:
        st.warning("Run scan first")
        return

    df = pd.DataFrame(st.session_state.results)

    col1, col2 = st.columns(2)
    col1.plotly_chart(px.pie(df, names="severity"), use_container_width=True)
    col2.plotly_chart(px.bar(df, x="type"), use_container_width=True)

# ---------------- MAIN ----------------
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