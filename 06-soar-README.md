# 06 — AI-Powered SOAR Playbook Engine 🚨

An intelligent Security Orchestration, Automation and Response (SOAR) engine that classifies any security alert, enriches it with real-time threat intelligence, and generates a structured incident response playbook — ready for immediate analyst execution.

---

## 🚨 The Problem

When a security alert fires, analysts waste precious time figuring out what to do next. Generic runbooks don't account for the specific context of each incident — who the attacker is, how dangerous the IP is, what systems are exposed. This engine automates the entire triage and playbook generation pipeline in under 60 seconds.

---

## ✅ What It Does

- Accepts any raw security alert as natural language input
- Classifies alert type using Claude AI (8 supported categories)
- Extracts IP addresses and enriches them via AbuseIPDB, VirusTotal, Shodan
- Generates a complete, intelligence-driven incident response playbook
- Assigns severity, SLA, ownership tier, and escalation decision
- Saves playbook to timestamped `.txt` file for analyst execution

---

## 🎯 Supported Alert Types

| Type | Description |
|------|-------------|
| `brute_force` | SSH/RDP/web login attack attempts |
| `phishing` | Suspicious email with malicious indicators |
| `malware_detected` | Endpoint AV/EDR detection |
| `lateral_movement` | Internal network traversal activity |
| `data_exfiltration` | Abnormal outbound data transfer |
| `privilege_escalation` | Unauthorized privilege gain |
| `ransomware` | File encryption or ransom indicators |
| `unknown` | Unclassified alerts |

---

## 📄 Sample Output

```
================================================
   AUTOMATED RESPONSE PLAYBOOK
================================================
Generated : Apr 15 2026 16:02:11
------------------------------------------------
ALERT TYPE: data_exfiltration
SEVERITY: HIGH
SLA: 2 hours
ASSIGNED TO: Incident Response Team

CONTEXT
  A user account experienced multiple failed authentication attempts from a
  high-risk IP address (AbuseIPDB: 96/100), followed by a successful login
  and abnormal outbound data transfer suggesting credential compromise and
  potential data exfiltration.

PLAYBOOK — EXECUTE IN ORDER

STEP 1 — IMMEDIATE CONTAINMENT [0-30 minutes]
  □ Disable the impacted user account temporarily
  □ Revoke all active sessions for the user
  □ Block source IP 185.220.101.45 at firewall and proxy
  □ Isolate affected endpoint if actively transferring data

STEP 2 — INVESTIGATE SCOPE [30-60 minutes]
  □ Review sign-in logs for other logins from 185.220.101.45
  □ Identify other users authenticating from same ASN
  □ Examine DeviceNetworkEvents for large outbound transfers
  □ Search for similar activity across past 30 days

...

ESCALATION DECISION: Yes — Confirmed high-risk IP with strong evidence
of credential compromise and external data transfer.
================================================
```

---

## 📁 Files

| File | Description |
|------|-------------|
| `soar_playbook.py` | Main playbook engine |
| `.env.example` | API key template |
| `requirements.txt` | Python dependencies |

---

## ⚙️ Setup

**Step 1 — Install dependencies**
```bash
pip install -r requirements.txt
```

**Step 2 — Configure API keys**
```bash
# Rename .env.example to .env and add your keys
# Requires: ANTHROPIC_API_KEY, ABUSEIPDB_API_KEY, VIRUSTOTAL_API_KEY, SHODAN_API_KEY
```

**Step 3 — Run**
```bash
python soar_playbook.py
```

**Step 4 — Paste your alert when prompted**
```
Paste alert text: Failed SSH login attempts: 847 attempts from 192.168.1.105...
```

---

## 🧪 Test Alerts

```
# Brute Force
Failed SSH login attempts: 847 attempts from 192.168.1.105 in last 10 minutes targeting root, admin, ubuntu

# Data Exfiltration
Multiple failed login attempts from 185.220.101.45 followed by successful authentication. Large outbound HTTPS traffic observed shortly after.

# Malware
Endpoint alert: Trojan.GenericKD detected on DESKTOP-ABC123, file hash 44d88612fea8a8f36de82e1278abb02f quarantined

# Phishing
Suspicious email detected: Reply-To mismatch, 3 URLs, urgency language, sender spoofing PayPal
```

---

## 🏗️ Architecture

```
Raw Alert Input
      ↓
classify_alert()    ← Claude AI classifies alert type + severity
      ↓
enrich_alert()      ← Extracts IPs → queries AbuseIPDB, VirusTotal, Shodan
      ↓
generate_playbook() ← Claude AI generates intelligence-driven playbook
      ↓
Saved .txt file     ← Timestamped playbook ready for analyst execution
```

---

## 💡 Key Concepts Used

- **AI alert classification** — structured JSON output from LLM
- **Regex IP extraction** — automatic IOC detection from alert text
- **Multi-API threat enrichment** — real-time context from 3 sources
- **Intelligence-driven playbooks** — enrichment data feeds playbook generation
- **Modular architecture** — reuses tools from Projects 04 and 05

---

## 🔮 Potential Improvements

- [ ] Support batch alert processing from SIEM export
- [ ] Add MITRE ATT&CK technique mapping per alert type
- [ ] Slack/Teams webhook to deliver playbook automatically
- [ ] Export playbook as PDF for formal incident documentation
- [ ] Connect to ticketing systems (Jira, ServiceNow) to auto-create incidents
- [ ] Add LangGraph supervisor for multi-alert correlation

---

*Part of the [AI Security Portfolio](../README.md) — Project 06 of many.*
