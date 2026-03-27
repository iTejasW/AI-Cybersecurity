# 03 — AI-Powered Phishing Email Analyzer 🎣

An AI-powered security tool that parses raw email files, extracts phishing indicators programmatically, and uses Claude AI to deliver a structured verdict with confidence score — ready for immediate SOC use.

---

## 🚨 The Problem

Phishing is the #1 attack vector globally — over 90% of breaches start with a phishing email. SOC teams receive dozens of reported emails daily. Manual triage is slow, inconsistent, and error-prone. This tool automates the entire analysis pipeline in seconds.

---

## ✅ What It Does

- Parses raw `.eml` email files using Python's built-in `email` library
- Extracts sender, reply-to, subject, body, and all URLs
- Runs 5 programmatic phishing indicator checks
- Feeds all data to Claude AI for deep contextual analysis
- Returns a structured verdict: PHISHING / SUSPICIOUS / LEGITIMATE
- Assigns confidence score (0–100%) and risk level
- Saves full report to a `.txt` file

---

## 🔍 Indicator Checks

| # | Check | What It Detects |
|---|-------|-----------------|
| 1 | Reply-To mismatch | Reply-To domain differs from sender domain |
| 2 | Urgency language | Words like "urgent", "suspended", "verify immediately" |
| 3 | Suspicious TLDs | URLs ending in .ru, .tk, .xyz, .top, .click, .link |
| 4 | URL volume | 3 or more URLs in a single email |
| 5 | Display name mismatch | Sender display name doesn't match actual domain |

---

## 📄 Sample Output

```
========================================
   PHISHING ANALYSIS REPORT
========================================
Subject  : Urgent: Your PayPal account has been limited
Sender   : security@paypa1.com
Reply-To : harvester@suspicious.ru
URLs     : 3 found
----------------------------------------
VERDICT: PHISHING
CONFIDENCE: 97%
RISK LEVEL: HIGH

INDICATORS FOUND:
- Reply-To domain differs from sender domain
- Urgency language present in subject and body
- Multiple suspicious URLs including .ru domain
- High number of embedded URLs
- Sender domain resembles a high-value brand but is misspelled
  ("paypa1.com" instead of "paypal.com")

RECOMMENDED ACTION:
- Block sender domain and associated Reply-To domain in mail gateway
- Add all extracted URLs to the URL blacklist and sandbox for analysis
- Notify the affected user and check for any interactions
- Search environment for similar messages using the same infrastructure

EXPLANATION:
This email exhibits multiple high-confidence phishing indicators,
including domain spoofing, urgency language, a mismatched Reply-To
domain, and URLs leading to non-PayPal infrastructure. The sender
domain visually impersonates PayPal, and the presence of a .ru
harvesting URL significantly increases threat severity.
========================================
```

---

## 📁 Files

| File | Description |
|------|-------------|
| `phishing_analyzer.py` | Main analysis script |
| `sample_phishing.eml` | Sample phishing email for testing |
| `.env.example` | API key template — rename to `.env` |
| `requirements.txt` | Python dependencies |

---

## ⚙️ Setup

**Step 1 — Install dependencies**
```bash
pip install -r requirements.txt
```

**Step 2 — Configure API key**
```bash
# Rename .env.example to .env
# Add your Anthropic API key inside
# Get your key at: https://console.anthropic.com
```

**Step 3 — Run the analyzer**
```bash
python phishing_analyzer.py
```

**Step 4 — Enter the path to your .eml file when prompted**
```
Enter path to .eml file: sample_phishing.eml
```

---

## 🧪 Test Emails to Try

Create your own `.eml` test files to see how the tool handles different scenarios:

| Scenario | What to test |
|----------|-------------|
| Obvious phishing | Spoofed domain + urgency + suspicious URLs |
| Subtle phishing | No urgency language but mismatched reply-to |
| Legitimate email | Normal corporate email with no indicators |
| Edge case | Email with many URLs but no other indicators |

---

## 🔐 Security Note

**Never commit your `.env` file to GitHub.** The `.gitignore` in this repo already blocks it. Only `.env.example` is safe to push.

---

## 💡 Key Concepts Used

- **Python `email` library** — parsing raw RFC 2822 email format
- **Multipart email handling** — correctly extracting body from complex emails
- **Regex URL extraction** — pulling all URLs from email body
- **Programmatic indicator logic** — rule-based detection before AI
- **Prompt engineering** — structured AI prompts for consistent SOC output
- **Claude API** — deep contextual phishing analysis

---

## 🔮 Potential Improvements

- [ ] HTML email body parsing and link extraction
- [ ] VirusTotal API integration to check URLs in real time
- [ ] Batch mode — analyze an entire folder of `.eml` files
- [ ] WHOIS lookup on sender domain for registration date
- [ ] Slack/Teams webhook to post verdict automatically
- [ ] Export results as JSON for SIEM ingestion

---

*Part of the [AI Security Portfolio](../README.md) — Project 03 of many.*
