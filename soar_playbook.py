import re
import os
import sys
import json
from datetime import datetime
from anthropic import Anthropic
from dotenv import load_dotenv

# ── Path setup for reusing previous project tools ─────────────────────────────
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '04-threat-intel-dashboard'))
from threat_intel_core import check_abuseipdb, check_virustotal, check_shodan

load_dotenv()
client = Anthropic()


# ── Alert Types ───────────────────────────────────────────────────────────────

ALERT_TYPES = [
    "brute_force",
    "phishing",
    "malware_detected",
    "lateral_movement",
    "data_exfiltration",
    "privilege_escalation",
    "ransomware",
    "unknown"
]


# ====================================================
#              STEP 1 — CLASSIFY ALERT
# ====================================================

def classify_alert(alert_text: str) -> dict:
    prompt = f"""
You are a SOC analyst. Classify this security alert into exactly one category.

Alert: {alert_text}

Categories: {', '.join(ALERT_TYPES)}

Respond ONLY with valid JSON in this exact format with no extra text:
{{
    "alert_type": "category_name",
    "confidence": 95,
    "key_indicators": ["indicator1", "indicator2"],
    "severity": "HIGH"
}}
"""
    message = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=200,
        messages=[{"role": "user", "content": prompt}]
    )

    return json.loads(message.content[0].text)


# ====================================================
#              STEP 2 — ENRICH ALERT
# ====================================================

def extract_ips(text: str) -> list:
    pattern = re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
    )
    return list(set(pattern.findall(text)))


def enrich_alert(alert_text: str) -> dict:
    enrichment = {}
    ips = extract_ips(alert_text)

    if not ips:
        return enrichment

    print(f"[+] Found {len(ips)} IP(s) — enriching with threat intel...")

    for ip in ips:
        intel = {
            "abuseipdb":  check_abuseipdb(ip),
            "virustotal": check_virustotal(ip, "ip"),
            "shodan":     check_shodan(ip)
        }
        enrichment[ip] = intel
        print(f"    {ip} → AbuseIPDB: {intel['abuseipdb'].get('abuseConfidenceScore')}/100")

    return enrichment


# ====================================================
#              STEP 3 — GENERATE PLAYBOOK
# ====================================================

def generate_playbook(alert_text: str, classification: dict, enrichment: dict = {}) -> str:

    # Build enrichment summary for the prompt
    enrichment_summary = ""
    for ip, intel in enrichment.items():
        abuse = intel.get("abuseipdb", {})
        vt    = intel.get("virustotal", {})
        sh    = intel.get("shodan", {})
        enrichment_summary += f"""
  IP: {ip}
    AbuseIPDB : {abuse.get('abuseConfidenceScore')}/100 · {abuse.get('totalReports')} reports · {abuse.get('isp')}
    VirusTotal: {vt.get('malicious')}/{vt.get('total')} engines flagged
    Shodan    : Ports {sh.get('open_ports')} · {sh.get('org')}
"""

    prompt = f"""
You are a senior SOC analyst writing a response playbook.

ALERT: {alert_text}

CLASSIFICATION:
  Type      : {classification['alert_type']}
  Severity  : {classification['severity']}
  Confidence: {classification['confidence']}%
  Indicators: {', '.join(classification['key_indicators'])}

THREAT INTEL ENRICHMENT:
{enrichment_summary if enrichment_summary else '  No IPs detected in alert'}

Generate a complete incident response playbook using the enrichment data
to add specific context to your containment and investigation steps.

Structure it EXACTLY like this:

ALERT TYPE: [type]
SEVERITY: [level]
SLA: [response time — CRITICAL=30mins, HIGH=2hrs, MEDIUM=4hrs, LOW=24hrs]
ASSIGNED TO: [Tier 1 / Tier 2 / Incident Response Team based on severity]

CONTEXT
  Summarize what is happening in 2-3 lines.

PLAYBOOK — EXECUTE IN ORDER

STEP 1 — IMMEDIATE CONTAINMENT [timeframe]
  List specific containment actions with checkboxes □

STEP 2 — INVESTIGATE SCOPE [timeframe]
  List specific investigation steps with checkboxes □

STEP 3 — ASSESS DAMAGE [timeframe]
  List specific damage assessment steps with checkboxes □

STEP 4 — REMEDIATION [timeframe]
  List specific remediation steps with checkboxes □

STEP 5 — DOCUMENTATION & CLOSURE
  List documentation requirements with checkboxes □

ESCALATION DECISION: [Yes/No — with reason]
"""

    message = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=1500,
        messages=[{"role": "user", "content": prompt}]
    )

    return message.content[0].text


# ====================================================
#              MAIN
# ====================================================

def main():
    print("\n================================================")
    print("   AI-POWERED SOAR PLAYBOOK ENGINE")
    print("================================================")

    alert_text = input("\nPaste alert text: ").strip()

    print("\n[+] Classifying alert...")
    classification = classify_alert(alert_text)
    print(f"[+] Type      : {classification['alert_type']}")
    print(f"[+] Severity  : {classification['severity']}")
    print(f"[+] Confidence: {classification['confidence']}%")

    enrichment = enrich_alert(alert_text)

    print("[+] Generating response playbook...")
    playbook = generate_playbook(alert_text, classification, enrichment)

    output = f"""
================================================
   AUTOMATED RESPONSE PLAYBOOK
================================================
Generated : {datetime.now().strftime('%b %d %Y %H:%M:%S')}
------------------------------------------------
{playbook}
================================================
"""

    print(output)

    filename = f"playbook_{classification['alert_type']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(filename, "w") as f:
        f.write(output)
    print(f"[+] Playbook saved to: {filename}")


if __name__ == "__main__":
    main()
