# 04 — AI-Powered Threat Intelligence Dashboard 🛡️

A multi-source threat intelligence aggregator that queries AbuseIPDB, VirusTotal, and Shodan in parallel, then uses Claude AI to correlate findings and generate a structured morning threat briefing — ready for immediate SOC use.

---

## 🚨 The Problem

SOC teams waste hours every morning manually checking multiple threat intel sources for IOCs. Each source has different APIs, different data formats, and different coverage. This tool unifies all of them into a single automated pipeline with AI-powered correlation.

---

## ✅ What It Does

- Reads a list of IOCs from `iocs.txt` (IPs, domains, file hashes)
- Automatically detects IOC type using regex
- Queries the right APIs for each IOC type
- Correlates multi-source findings using Claude AI
- Generates a structured morning threat briefing saved to file

---

## 🔌 API Sources

| Source | IOC Types | What It Provides |
|--------|-----------|-----------------|
| AbuseIPDB | IP | Abuse confidence score, total reports, ISP, country |
| VirusTotal | IP, Domain, Hash | Engine detections, malicious/suspicious counts |
| Shodan | IP | Open ports, organization, hostnames, OS |

---

## 🧠 IOC Type Detection

| Type | Example | Detection Method |
|------|---------|-----------------|
| IP Address | `45.33.32.156` | IPv4 regex (0–255 validation) |
| Domain | `suspicious-domain.ru` | Domain pattern regex |
| MD5 Hash | `44d88612...` | 32-char hex regex |
| SHA1 Hash | `da39a3ee...` | 40-char hex regex |
| SHA256 Hash | `e3b0c442...` | 64-char hex regex |

---

## 📄 Sample Output

```
========================================================
   MORNING THREAT INTELLIGENCE BRIEFING
   Generated: Mar 30 2026 16:32:12
========================================================
IOCs Analyzed : 3

--------------------------------------------------------
IOC  : 45.33.32.156
Type : IP
--------------------------------------------------------
VERDICT: MALICIOUS
RISK LEVEL: HIGH
CONFIDENCE: 91%

ANALYSIS:
The IP shows consistently high AbuseIPDB scores with substantial
malicious scanning activity reported. VirusTotal engines classify
it as probing/reconnaissance traffic, and Shodan confirms it belongs
to known scanning infrastructure.

RECOMMENDED ACTION:
Block the IP at the perimeter firewall and suppress repeated alerts
as this is a known scanner range.

--------------------------------------------------------
IOC  : suspicious-domain.ru
Type : DOMAIN
--------------------------------------------------------
VERDICT: MALICIOUS
RISK LEVEL: CRITICAL
CONFIDENCE: 96%

ANALYSIS:
VirusTotal reports multiple malicious detections and associations
with phishing and malware distribution.

RECOMMENDED ACTION:
Block the domain at DNS/web filtering layers and audit recent
connections from internal hosts.

--------------------------------------------------------
IOC  : 44d88612fea8a8f36de82e1278abb02f
Type : HASH
--------------------------------------------------------
VERDICT: MALICIOUS
RISK LEVEL: CRITICAL
CONFIDENCE: 99%

ANALYSIS:
VirusTotal engines overwhelmingly classify the hash as a trojan
family used for credential theft.

RECOMMENDED ACTION:
Block the hash everywhere, scan endpoints for presence, and reset
credentials if infection is suspected.

========================================================
```

---

## 📁 Files

| File | Description |
|------|-------------|
| `threat_intel.py` | Main script — orchestrates the full pipeline |
| `threat_intel_core.py` | Core functions — API checks + AI correlation |
| `iocs.txt` | Input file — add your IOCs here |
| `.env.example` | API key template — rename to `.env` |
| `requirements.txt` | Python dependencies |

---

## ⚙️ Setup

**Step 1 — Get your API keys (all free tier)**

| Service | Sign Up |
|---------|---------|
| AbuseIPDB | https://www.abuseipdb.com/register |
| VirusTotal | https://www.virustotal.com/gui/join-us |
| Shodan | https://account.shodan.io/register |
| Anthropic | https://console.anthropic.com |

**Step 2 — Install dependencies**
```bash
pip install -r requirements.txt
```

**Step 3 — Configure API keys**
```bash
# Rename .env.example to .env and fill in your keys
```

**Step 4 — Add your IOCs**
```bash
# Edit iocs.txt — one IOC per line
# Supports: IPv4 addresses, domains, MD5/SHA1/SHA256 hashes
# Lines starting with # are comments
```

**Step 5 — Run**
```bash
python threat_intel.py
```

---

## 🔐 Security Note

**Never commit your `.env` file to GitHub.** The `.gitignore` blocks it automatically. Only `.env.example` is safe to push.

---

## 💡 Key Concepts Used

- **Multi-API integration** — three different APIs with different auth methods
- **IOC type detection** — automatic classification using regex
- **Modular architecture** — core functions separated from orchestration logic
- **Data correlation** — combining multi-source intel into unified AI analysis
- **Prompt engineering** — structured prompts for consistent threat verdict output
- **Error handling** — graceful failures when APIs are unavailable or rate-limited

---

## 🔮 Potential Improvements

- [ ] Add comment filtering in `iocs.txt` (lines starting with #)
- [ ] Add rate limiting handler with exponential backoff
- [ ] AlienVault OTX API integration for additional context
- [ ] Export report as JSON for SIEM ingestion
- [ ] Slack/Teams webhook to post briefing automatically every morning
- [ ] Batch processing with progress bar for large IOC lists
- [ ] Add EPSS score for CVE-related IOCs

---

*Part of the [AI Security Portfolio](../README.md) — Project 04 of many.*
