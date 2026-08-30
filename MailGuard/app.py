"""
Streamlit UI for SIH26106 - AI-Powered Email Threat Detection Platform
------------------------------------------------------------------------
Run with:  streamlit run app.py
"""

import streamlit as st
from detector import parse_email, analyze_threat

st.set_page_config(page_title="MailGuard", page_icon="🛡️", layout="centered")

st.title("🛡️ MailGuard")
st.caption("AI-Powered Email Threat Detection & Forensic Intelligence Platform | SIH26106 | Team Vigil")

# ---------- Input ----------

sample_phishing = """From: "Bank Support" <support@bank-secure-login.com>
Reply-To: attacker@totallyfake.ru
Subject: URGENT: Verify your account now
Authentication-Results: mx.google.com; spf=fail; dkim=fail; dmarc=fail
Received: from unknown (HELO mail.spamhost.com) (185.23.44.12) by mx.google.com

Dear Customer,

Your account has been suspended due to unusual activity.
Click here immediately to verify your account: http://bit.ly/fake-login

Regards,
Bank Security Team
"""

sample_clean = """From: "Team Lead" <lead@mycompany.com>
Reply-To: lead@mycompany.com
Subject: Weekly sync notes
Authentication-Results: mx.google.com; spf=pass; dkim=pass; dmarc=pass
Received: from mail.mycompany.com (203.0.113.5) by mx.google.com

Hi team,

Here are the notes from today's sync. Please review the doc at https://docs.mycompany.com/notes when you get a chance.

Thanks,
Lead
"""

col1, col2, col3 = st.columns(3)
with col1:
    load_phishing = st.button("Load phishing sample")
with col2:
    load_clean = st.button("Load clean sample")
with col3:
    clear = st.button("Clear")

if "email_text" not in st.session_state:
    st.session_state.email_text = ""

if load_phishing:
    st.session_state.email_text = sample_phishing
if load_clean:
    st.session_state.email_text = sample_clean
if clear:
    st.session_state.email_text = ""

uploaded_file = st.file_uploader("Upload a .eml file", type=["eml", "txt"])
if uploaded_file is not None:
    st.session_state.email_text = uploaded_file.read().decode("utf-8", errors="ignore")

email_text = st.text_area(
    "Or paste raw email source here (including headers):",
    value=st.session_state.email_text,
    height=280,
)

analyze = st.button("🔍 Analyze Email", type="primary")

# ---------- Output ----------

if analyze:
    if not email_text.strip():
        st.warning("Please paste or upload an email first.")
    else:
        parsed = parse_email(email_text)
        result = analyze_threat(parsed)

        st.divider()
        st.subheader("📋 Parsed Header Info")

        c1, c2 = st.columns(2)
        with c1:
            st.markdown(f"**From:** {parsed['sender']}")
            st.markdown(f"**Reply-To:** {parsed['reply_to'] or '—'}")
            st.markdown(f"**Subject:** {parsed['subject']}")
        with c2:
            st.markdown(f"**Sender IP:** `{parsed['sender_ip']}`")
            st.markdown(f"**SPF:** {parsed['spf']}")
            st.markdown(f"**DKIM:** {parsed['dkim']}")
            st.markdown(f"**DMARC:** {parsed['dmarc']}")

        st.divider()
        st.subheader("🚨 Threat Analysis")

        risk_color = {"Low": "green", "Medium": "orange", "High": "red"}[result["risk_level"]]
        st.markdown(
            f"### Risk Score: {result['score']}/100 — "
            f":{risk_color}[**{result['risk_level']} Risk**]"
        )
        st.progress(result["score"] / 100)

        st.markdown("**Flagged Signals:**")
        for flag in result["flags"]:
            st.markdown(f"- {flag}")

        if result["urls_found"]:
            with st.expander(f"🔗 {len(result['urls_found'])} link(s) found in email"):
                for url in result["urls_found"]:
                    flag_icon = "⚠️" if url in result["suspicious_urls"] else "✅"
                    st.markdown(f"{flag_icon} `{url}`")

        st.divider()
        st.subheader("📄 Forensic Summary (for report)")
        report_text = f"""EMAIL FORENSIC REPORT
=======================
Sender: {parsed['sender']}
Reply-To: {parsed['reply_to'] or 'N/A'}
Subject: {parsed['subject']}
Sender IP: {parsed['sender_ip']}
SPF: {parsed['spf']} | DKIM: {parsed['dkim']} | DMARC: {parsed['dmarc']}

Risk Score: {result['score']}/100 ({result['risk_level']} Risk)

Flagged Signals:
{chr(10).join('- ' + f for f in result['flags'])}
"""
        st.text_area("Copy-paste this into your forensic report / PPT appendix:", report_text, height=220)
        st.download_button("⬇️ Download Report (.txt)", report_text, file_name="forensic_report.txt")

st.divider()
st.caption("MailGuard — built by Team Vigil for Smart India Hackathon 2026 (SIH26106)")
