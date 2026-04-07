# 04 — AI-Powered Threat Intelligence Dashboard 🛡️

A multi-source threat intelligence aggregator that queries AbuseIPDB, VirusTotal, and Shodan in parallel, then uses Claude AI to correlate findings and generate a structured morning threat briefing — ready for immediate SOC use.

---

## 🚨 The Problem

SOC teams waste hours every morning manually checking multiple threat intel sources for IOCs. Each source has different APIs, different data formats, and different coverage. This tool unifies all of them into a single automated pipeline with AI-powered correlation.

---

## ✅ What It Does

- Reads a list of IOCs from `iocs.txt` (IPs, domains, file hashes, CVE)
- **Multi-Source Enrichment:** Queries AbuseIPDB, VirusTotal, Shodan, and AlienVault OTX in parallel.
- **Vulnerability Prioritization:** Fetches EPSS scores for CVEs to determine real-world exploit probability.
- **Resilient API Handling:** Uses exponential backoff to automatically handle rate limits (429 errors).
- **Clean Input Parsing:** Automatically detects IOC types and supports comments (#) in the input file.
- Correlates multi-source findings using Claude AI
- **SIEM-Ready Output:** Generates both a human-readable `.txt` brief and a structured `.json` report.

---

## 🔌 API Sources

| Source | IOC Types | What It Provides |
|--------|-----------|-----------------|
| AbuseIPDB | IP | Abuse score, total reports, ISP, and country |
| VirusTotal | IP, Domain, Hash | Engine detections and malicious/suspicious counts |
| Shodan | IP | Open ports, vulnerabilities, and hostnames |
| AlienVault OTX | IP, Domain, Hash, CVE | Community "Pulses," threat actor tags, and campaign names |
| FIRST.org | CVE | EPSS score (Exploit Prediction Scoring System) |

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
   Generated: Oct 24 2023 09:15:30
========================================================
IOCs Analyzed : 2

--------------------------------------------------------
IOC  : 45.33.32.156
Type : IP
--------------------------------------------------------
VERDICT: MALICIOUS
RISK LEVEL: HIGH
CONFIDENCE: 95%

ANALYSIS:
This IP address shows significant malicious activity across multiple 
datasets. AbuseIPDB reports a 100% confidence score with over 250 
recent reports of SSH brute-forcing. VirusTotal shows 12 security 
vendors flagging this as a known botnet node. AlienVault OTX links 
this IP to the 'Mirai-Variant' pulse. Shodan reveals open port 23 (Telnet), 
suggesting it is a compromised IoT device.

RECOMMENDED ACTIONS:
1. BLOCK: Apply an immediate block on the perimeter firewall for all 
   inbound and outbound traffic to this IP.
2. HUNT: Query SIEM logs for any successful SSH connections or 
   outbound Telnet traffic to this destination over the last 30 days.
3. HARDEN: Ensure all IoT devices on the network have Telnet disabled 
   and default credentials changed to prevent lateral movement.

--------------------------------------------------------
IOC  : CVE-2023-44487
Type : CVE
--------------------------------------------------------
VERDICT: MALICIOUS
RISK LEVEL: CRITICAL
CONFIDENCE: 100%

ANALYSIS:
This CVE refers to the 'HTTP/2 Rapid Reset' vulnerability. While the 
CVSS score is 7.5, the EPSS score is 94.12%, indicating a near-certain 
probability of active exploitation in the wild. AlienVault OTX identifies 
this as a primary technique used in recent record-breaking DDoS attacks. 

RECOMMENDED ACTIONS:
1. PATCH: Apply vendor-specific patches to load balancers, proxies, 
   and web servers (Nginx, Apache, IIS) immediately.
2. MITIGATE: If patching is delayed, disable HTTP/2 support or limit 
   the number of concurrent streams per connection at the edge.
3. MONITOR: Set up alerts for unusual spikes in HTTP/2 RST_STREAM 
   frames, which may indicate an ongoing "Rapid Reset" attack attempt.
========================================================
```
## 💾 Sample SIEM Export (.json)

[cite_start]The tool generates a structured JSON report for every run, designed for easy ingestion into SIEM or SOAR platforms. [cite: 1]

<details>
  <summary>Click to expand Sample JSON Output</summary>

  ```json
  [
      {
          "ioc": "45.33.32.156",
          "type": "ip",
          "intel": {
              "abuseipdb": { 
                  "abuseConfidenceScore": 100, 
                  "totalReports": 254 
              },
              "virustotal": { 
                  "malicious": 12, 
                  "total": 72 
              },
              "otx": { 
                  "pulse_count": 3, 
                  "threat_names": ["Mirai-Variant", "Brute-Force-List"] 
              },
              "shodan": { 
                  "open_ports": [23, 80, 8080] 
              }
          },
          "verdict": "VERDICT: MALICIOUS\nRISK LEVEL: HIGH\nANALYSIS: This IP is part of a Mirai botnet...\nRECOMMENDED ACTIONS: 1. Block on Firewall..."
      },
      {
          "ioc": "CVE-2023-44487",
          "type": "cve",
          "intel": {
              "epss": { 
                  "epss": "94.12%", 
                  "percentile": "0.987" 
              },
              "otx": { 
                  "pulse_count": 12, 
                  "threat_names": ["HTTP/2 Rapid Reset Campaign"] 
              }
          },
          "verdict": "VERDICT: MALICIOUS\nRISK LEVEL: CRITICAL\nANALYSIS: High exploitability vulnerability...\nRECOMMENDED ACTIONS: 1. Patch load balancers..."
      }
  ]
</details>



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

## 🚀 Enterprise Features Added
- [x] **Comment Filtering:** `iocs.txt` now ignores lines starting with `#`.
- [x] **Rate Limiting:** Implemented exponential backoff for API resilience.
- [x] **AlienVault OTX:** Added community-sourced threat context.
- [x] **JSON Export:** Structured data generated for SIEM/SOAR ingestion.
- [x] **EPSS Scoring:** Integrated exploit probability for CVE analysis.

## 🔮 Next Steps
- [ ] Add a progress bar for large batch processing.
- [ ] Integrate a Slack/Teams webhook for automated morning alerts.
- [ ] Build a dashboard UI using Streamlit.

---

*Part of the [AI Security Portfolio](../README.md) — Project 04 of many.*
