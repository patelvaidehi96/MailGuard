# MailGuard

AI-powered email threat detection and forensic intelligence platform | SIH26106 | Team Vigil

## Problem Statement

**SIH26106** — AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform
Theme: Blockchain & Cybersecurity | Category: Software | Organization: AICTE

## What it does

MailGuard analyzes any email (pasted text or `.eml` file) and instantly flags signs of phishing, spoofing, and malicious intent. It parses email headers, checks authentication results (SPF/DKIM/DMARC), scans for suspicious keywords and links, and produces a clear, explainable risk score along with a downloadable forensic report.

## Features

- Parses sender info, Reply-To, subject, body, and authentication headers
- Detects SPF/DKIM/DMARC failures (spoofing indicators)
- Flags Reply-To mismatches
- Scans for common phishing/urgency language
- Detects suspicious links (shorteners, raw IPs, obfuscated domains)
- Generates a 0–100 risk score mapped to Low / Medium / High
- Exports a downloadable forensic report

## Tech stack

- **Language:** Python
- **Frameworks/libraries:** Streamlit, Python `email` library, Regex
- **Future scope:** ML/NLP classifier, GeoIP API, cloud deployment

## How to run

```bash
pip install streamlit
streamlit run app.py
```

The app opens automatically in your browser at `localhost:8501`.

## Demo

Use the built-in "Load phishing sample" and "Load clean sample" buttons to see the tool in action instantly, or upload your own `.eml` file.

## Demo Video

Watch the full demo here: 

https://github.com/user-attachments/assets/95be9dec-e803-41fb-bafa-f553216fdd91

The video demonstrates:
- Analyzing a phishing email (high risk detection)
- Analyzing a clean email (low risk detection)
- Generating and downloading the forensic report
## Team

**Team Vigil** — Smart India Hackathon 2026



