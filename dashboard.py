#!/usr/bin/env python3
"""
Zainab Mini-SOC: Automated Incident Response & Threat Monitoring Console
Author: Zainab (SOC Analyst Portfolio)
Framework: Streamlit & SQLite3
"""

import streamlit as st
import pandas as pd
import sqlite3
import os

DB_FILE = os.path.expanduser("~/mini_soc/soc_incidents.db")
CONTAINMENT_LOG = os.path.expanduser("~/mini_soc/containment.log")

st.set_page_config(
    page_title="Zainab Mini-SOC Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for Dark Modern SOC Look
st.markdown("""
<style>
    .metric-card {
        background-color: #1E222D;
        border: 1px solid #2E3440;
        border-radius: 8px;
        padding: 15px;
        text-align: center;
    }
    .stDataFrame {
        border-radius: 8px;
    }
</style>
""", unsafe_allow_html=True)

def load_data():
    if not os.path.exists(DB_FILE):
        return pd.DataFrame()
    conn = sqlite3.connect(DB_FILE)
    df = pd.read_sql_query("SELECT * FROM incidents ORDER BY timestamp DESC", conn)
    conn.close()
    return df

def update_status(inc_id, new_status):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("UPDATE incidents SET status = ? WHERE incident_id = ?", (new_status, inc_id))
    conn.commit()
    conn.close()

# ----------------- SIDEBAR -----------------
with st.sidebar:
    st.image("https://img.icons8.com/color/96/000000/shield.png", width=70)
    st.title("Zainab Mini-SOC")
    st.markdown("**Role:** Tier 1 / Tier 2 SOC Analyst Console")
    st.markdown("**Architecture:** Wazuh SIEM + Context SOAR Engine")
    st.divider()
    if st.button("🔄 Refresh Data", use_container_width=True):
        st.rerun()
    st.info("💡 Real-time monitoring feed integrated with Telegram Bot & SQLite.")

# ----------------- MAIN VIEW -----------------
st.title("🛡️ Automated SOC Incident Response Console")
st.caption("Live Triage, Threat Intelligence Mapping, and Containment Operations")

df = load_data()

if df.empty:
    st.warning("⚠️ No incidents found in the database. Please run triage_engine.py first.")
    st.stop()

# Calculations
total_incidents = len(df)
high_critical = len(df[df['risk_rating'].isin(['HIGH', 'CRITICAL'])])
contained_count = len(df[df['status'] == 'CONTAINED'])
raw_estimated = df['aggregated_count'].sum() if 'aggregated_count' in df.columns else total_incidents * 8
reduction_rate = ((raw_estimated - total_incidents) / raw_estimated * 100) if raw_estimated > 0 else 0

# 1. TOP METRICS
col1, col2, col3, col4 = st.columns(4)
col1.metric("Raw Security Alerts", f"{raw_estimated}", help="Total raw telemetry events ingested by Wazuh")
col2.metric("Consolidated Incidents", f"{total_incidents}", help="Deduplicated actionable security incidents")
col3.metric("High / Critical Threats", f"{high_critical}", delta="Action Required", delta_color="inverse")
col4.metric("Alert Reduction Rate", f"{reduction_rate:.1f}%", delta="Fatigue Reduced", delta_color="normal")

st.divider()

# 2. CHARTS SECTION
col_chart1, col_chart2 = st.columns([1, 1])

with col_chart1:
    st.subheader("📊 Threats by Attack Type")
    attack_counts = df['alert_type'].value_counts()
    st.bar_chart(attack_counts, color="#FF4B4B")

with col_chart2:
    st.subheader("🎯 Risk Severity Distribution")
    rating_counts = df['risk_rating'].value_counts()
    st.bar_chart(rating_counts, color="#FFAA00")

st.divider()

# 3. INCIDENTS DATA TABLE
st.subheader("🚨 Active Incident Registry")
display_cols = ['incident_id', 'risk_rating', 'risk_score', 'status', 'source_ip', 'mitre_technique', 'action_taken', 'alert_type']
st.dataframe(
    df[display_cols],
    use_container_width=True,
    hide_index=True
)

st.divider()

# 4. INCIDENT INVESTIGATION WORKBENCH
st.subheader("🔍 Incident Investigation & Analyst Action")

selected_id = st.selectbox("Select Incident to Investigate:", df['incident_id'].tolist())

if selected_id:
    inc = df[df['incident_id'] == selected_id].iloc[0]

    inv_col1, inv_col2 = st.columns([2, 1])

    with inv_col1:
        st.markdown(f"### Incident Details: `{inc['incident_id']}`")
        st.markdown(f"**Alert Description:** {inc['alert_type']}")
        st.markdown(f"**Source Entity:** `IP: {inc['source_ip']}` | `User: {inc['source_user']}`")
        st.markdown(f"**MITRE ATT&CK:** `{inc['mitre_technique']}`")
        st.markdown(f"**Threat Intelligence Verdict:** `{inc['threat_intel']}`")
        
        st.info(f"**🔬 Forensic Evidence:**\n\n{inc['evidence']}")
        st.success(f"**⚡ Automated Action Executed:** `{inc['action_taken']}`")

    with inv_col2:
        st.markdown("### Analyst Workflow")
        st.markdown(f"**Current Status:** `{inc['status']}`")
        st.markdown(f"**Risk Score:** `{inc['risk_score']}/100 [{inc['risk_rating']}]`")

        new_status = st.selectbox(
            "Update Status:",
            ["OPEN", "INVESTIGATING", "CONTAINED", "CLOSED", "FALSE_POSITIVE"],
            index=["OPEN", "INVESTIGATING", "CONTAINED", "CLOSED", "FALSE_POSITIVE"].index(inc['status']) if inc['status'] in ["OPEN", "INVESTIGATING", "CONTAINED", "CLOSED", "FALSE_POSITIVE"] else 0
        )

        if st.button("💾 Save Status Update", use_container_width=True):
            update_status(selected_id, new_status)
            st.toast(f"Status updated to {new_status} for {selected_id}!")
            st.rerun()

# 5. CONTAINMENT AUDIT LOG
with st.expander("📜 View SOAR Containment Audit Log (Automated Firewall Policy)"):
    if os.path.exists(CONTAINMENT_LOG):
        with open(CONTAINMENT_LOG, "r") as f:
            st.code(f.read(), language="text")
    else:
        st.text("No containment actions recorded yet.")
