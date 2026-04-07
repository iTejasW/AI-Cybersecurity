# AI Security Agent (ReAct-Based)

This project implements a **ReAct-based AI Security Agent** capable of reasoning over security investigations and orchestrating multiple security tools automatically.

The agent understands natural language, decides which tools to invoke (CVE analysis, phishing analysis, threat intelligence), chains tool outputs, and produces analyst-ready summaries.
Risk-Based Prioritization: The agent is programmed to treat CVEs with an EPSS score > 10% as critical, regardless of base CVSS, reflecting real-world exploitability.

---

## 🛠️ Tools & Capabilities
- **analyze_cve**: Fetches NVD data and generates a strategic threat brief.
- **analyze_phishing**: Parses `.eml` files, extracts indicators, and detects intent.
- **analyze_iocs**: 
    - **Multi-Source Enrichment**: Queries AbuseIPDB, VirusTotal, and Shodan.
    - **Vulnerability Intel**: Fetches **EPSS scores** to predict exploit probability.
    - **Community Context**: Integrates **AlienVault OTX** pulses and threat actor tags.

---

## 🧠 Architecture Overview

```
User Input
   ↓
AI Security Agent (ReAct Loop)
   ↓
Tool Invocation (CVE / Phishing / Intel)
   ↓
Tool Results
   ↓
AI Reasoning → Final Verdict
```

The agent follows the **Reason → Act → Observe** (ReAct) pattern.

---

## 📂 Project Structure

```
05-security-agent/
├── agent.py
├── agent_tools.py
├── requirements.txt
├── .env.example
└── README.md
```

---

## 🚀 How to Run

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Create `.env` from the example:
```bash
cp .env.example .env
```
Add your API keys.

3. Run the agent:
```bash
python agent.py
```

---

## ✅ Example Queries

- `Analyze CVE-2021-44228`
- `Check this IP: 45.33.32.156`
- `Analyze phishing email at ./samples/invoice.eml`
- `Check these IOCs: evil.com, 8.8.8.8`

---

## 🎯 Output Format

The agent always responds with:
1. **VERDICT** — Severity summary
2. **FINDINGS** — Tool results
3. **ACTIONS** — Recommended next steps

---

## 🛡️ Disclaimer
This project is for educational and research purposes only. Do not use against systems you do not own or have permission to test.
