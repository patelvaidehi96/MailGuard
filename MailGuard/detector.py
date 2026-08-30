"""
Core Email Threat Detector for SIH26106
-----------------------------------------
Takes raw email text (.eml format) and returns:
  - parsed header info (sender, IP, SPF/DKIM/DMARC status)
  - a list of flagged suspicious signals
  - an overall risk score: Low / Medium / High

No external services needed. Pure Python standard library + simple rules.
"""

import re
import email
from email import policy
from email.parser import BytesParser, Parser


# ---------- 1. Rule data (tweak/expand these anytime) ----------

SUSPICIOUS_KEYWORDS = [
    "urgent action required", "verify your account", "suspended",
    "click here immediately", "confirm your password", "you have won",
    "limited time offer", "act now", "wire transfer", "gift card",
    "update your billing", "unusual activity", "reset your password",
    "final notice", "claim your prize",
]

URL_PATTERN = re.compile(r"https?://[^\s\"'>]+")

# Very small list of known-shady link patterns, expand as you like
SUSPICIOUS_URL_SIGNALS = [
    r"bit\.ly", r"tinyurl", r"\d+\.\d+\.\d+\.\d+",  # raw IP in link
    r"@",          # user@host style obfuscation
    r"-secure-", r"-verify-", r"login.*\.(?!com|org|edu|gov)[a-z]{2,}",
]


# ---------- 2. Parsing ----------

def parse_email(raw_text: str):
    """Parse raw email text and pull out useful header fields."""
    msg = Parser(policy=policy.default).parsestr(raw_text)

    sender = msg.get("From", "Unknown")
    subject = msg.get("Subject", "(no subject)")
    reply_to = msg.get("Reply-To", "")

    # Get plain text body
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                body += part.get_content()
    else:
        body = msg.get_content()

    # Authentication results (SPF/DKIM/DMARC) - usually in Authentication-Results header
    auth_header = msg.get("Authentication-Results", "")
    spf_status = _extract_auth_status(auth_header, "spf")
    dkim_status = _extract_auth_status(auth_header, "dkim")
    dmarc_status = _extract_auth_status(auth_header, "dmarc")

    # Try to find the originating IP from the last "Received" header
    received_headers = msg.get_all("Received", [])
    sender_ip = _extract_ip(received_headers[-1]) if received_headers else "Not found"

    return {
        "sender": sender,
        "reply_to": reply_to,
        "subject": subject,
        "body": body,
        "sender_ip": sender_ip,
        "spf": spf_status,
        "dkim": dkim_status,
        "dmarc": dmarc_status,
    }


def _extract_auth_status(auth_header: str, mechanism: str) -> str:
    match = re.search(rf"{mechanism}=(\w+)", auth_header, re.IGNORECASE)
    return match.group(1).lower() if match else "not present"


def _extract_ip(received_header: str) -> str:
    match = re.search(r"\[?(\d{1,3}(?:\.\d{1,3}){3})\]?", received_header)
    return match.group(1) if match else "Not found"


# ---------- 3. Threat scoring ----------

def analyze_threat(parsed: dict):
    """Run rule-based checks and return flags + risk score."""
    flags = []
    score = 0

    # --- Authentication checks ---
    if parsed["spf"] in ("fail", "softfail"):
        flags.append(f"SPF check failed ({parsed['spf']}) - sender domain may be spoofed")
        score += 25
    if parsed["dkim"] == "fail":
        flags.append("DKIM signature failed - message may have been tampered with")
        score += 25
    if parsed["dmarc"] == "fail":
        flags.append("DMARC policy failed - domain alignment issue")
        score += 15

    # --- Reply-To mismatch (classic phishing trick) ---
    if parsed["reply_to"] and parsed["reply_to"] not in parsed["sender"]:
        flags.append(f"Reply-To ({parsed['reply_to']}) differs from From address - possible spoofing")
        score += 15

    # --- Keyword checks in subject + body ---
    text = (parsed["subject"] + " " + parsed["body"]).lower()
    matched_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in text]
    if matched_keywords:
        flags.append(f"Suspicious phishing language found: {', '.join(matched_keywords[:3])}")
        score += min(20, 5 * len(matched_keywords))

    # --- URL checks ---
    urls = URL_PATTERN.findall(parsed["body"])
    suspicious_urls = []
    for url in urls:
        for pattern in SUSPICIOUS_URL_SIGNALS:
            if re.search(pattern, url, re.IGNORECASE):
                suspicious_urls.append(url)
                break
    if suspicious_urls:
        flags.append(f"{len(suspicious_urls)} suspicious link(s) detected (shortened/obfuscated/IP-based)")
        score += min(25, 10 * len(suspicious_urls))

    # --- Final risk level ---
    score = min(score, 100)
    if score >= 60:
        risk_level = "High"
    elif score >= 30:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    if not flags:
        flags.append("No suspicious signals detected")

    return {
        "score": score,
        "risk_level": risk_level,
        "flags": flags,
        "urls_found": urls,
        "suspicious_urls": suspicious_urls,
    }


# ---------- 4. Quick manual test ----------

if __name__ == "__main__":
    sample_email = """From: "Bank Support" <support@bank-secure-login.com>
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
    parsed = parse_email(sample_email)
    result = analyze_threat(parsed)

    print("--- Parsed Email ---")
    for k, v in parsed.items():
        if k != "body":
            print(f"{k}: {v}")

    print("\n--- Threat Analysis ---")
    print(f"Risk Score: {result['score']}/100 -> {result['risk_level']}")
    print("Flags:")
    for f in result["flags"]:
        print(f"  - {f}")
