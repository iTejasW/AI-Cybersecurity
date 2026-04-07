import sys
import os

# =============================================
# Extend Python path to reuse previous projects
# =============================================

sys.path.append(os.path.join(os.path.dirname(__file__), '..', '02-cve-threat-brief'))
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '03-phishing-analyzer'))
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '04-threat-intel-dashboard'))

# =============================================
# Import security tooling from previous projects
# =============================================

from cve_brief import get_cve_data, generate_threat_brief
from phishing_analyzer import parse_email, extract_indicators, analyze_with_ai
from threat_intel_core import (
    detect_ioc_type,
    check_abuseipdb,
    check_virustotal,
    check_shodan,
    check_otx,
    get_epss_score,
    correlate_with_ai,
)

# ====================================================
# TOOL DEFINITIONS — read by the AI model
# ====================================================

TOOL_DEFINITIONS = [
    {
        "name": "analyze_cve",
        "description": "Fetch CVE details and generate an AI-powered threat brief. Use when a CVE ID is mentioned.",
        "input_schema": {
            "type": "object",
            "properties": {
                "cve_id": {
                    "type": "string",
                    "description": "CVE ID to analyze (e.g. CVE-2021-44228)",
                }
            },
            "required": ["cve_id"],
        },
    },
    {
        "name": "analyze_phishing",
        "description": "Analyze a phishing email (.eml) for malicious indicators.",
        "input_schema": {
            "type": "object",
            "properties": {
                "filepath": {
                    "type": "string",
                    "description": "Path to the .eml email file",
                }
            },
            "required": ["filepath"],
        },
    },
    {
        "name": "analyze_iocs",
        "description": "Investigate IOCs (IPs, domains, hashes, and CVE IDs) using multi-source intelligence (AbuseIPDB, VirusTotal, Shodan, OTX, and EPSS).",
        "input_schema": {
            "type": "object",
            "properties": {
                "iocs": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of IOCs to analyze (e.g. IPs, domains, hashes, or CVE-YYYY-NNNN)",
                }
            },
            "required": ["iocs"],
        },
    },
]

# ====================================================
# TOOL EXECUTORS — real Python logic
# ====================================================

def run_analyze_cve(cve_id: str) -> str:
    cve_data = get_cve_data(cve_id)
    if not cve_data:
        return f"CVE {cve_id} not found."

    brief = generate_threat_brief(cve_data)
    return f"""
CVE ID   : {cve_data['cve_id']}
Severity : {cve_data['severity']} ({cve_data['cvss_score']})
Published: {cve_data['published']}

{brief}
"""


def run_analyze_phishing(filepath: str) -> str:
    if not os.path.exists(filepath):
        return f"File not found: {filepath}"

    parsed = parse_email(filepath)
    indicators = extract_indicators(parsed)
    verdict = analyze_with_ai(parsed, indicators)

    return f"""
Subject   : {parsed['subject']}
Sender    : {parsed['sender']}
Reply-To  : {parsed['reply_to']}
URLs      : {len(parsed['urls'])}
Indicators: {len(indicators)}

{verdict}
"""


def run_analyze_iocs(iocs: list) -> str:
    results = []

    for ioc in iocs:
        ioc_type = detect_ioc_type(ioc)
        intel = {}

        if ioc_type == "ip":
            intel["abuseipdb"] = check_abuseipdb(ioc)
            intel["virustotal"] = check_virustotal(ioc, ioc_type)
            intel["shodan"] = check_shodan(ioc)
            intel["otx"] = check_otx(ioc, ioc_type) # Added OTX
        elif ioc_type in ("domain", "hash"):
            intel["virustotal"] = check_virustotal(ioc, ioc_type)
            intel["otx"] = check_otx(ioc, ioc_type) # Added OTX
        elif ioc_type == "cve":
            intel["epss"] = get_epss_score(ioc)     # Added EPSS
            intel["otx"] = check_otx(ioc, ioc_type) # Added OTX
        else:
            results.append(f"{ioc}: Unknown IOC type")
            continue

        verdict = correlate_with_ai(ioc, ioc_type, intel)
        results.append(f"IOC: {ioc}\n{verdict}")

    return "\n\n---\n\n".join(results)

# ====================================================
# TOOL DISPATCHER — routes AI calls to executors
# ====================================================

def execute_tool(tool_name: str, tool_input: dict) -> str:
    if tool_name == "analyze_cve":
        return run_analyze_cve(tool_input["cve_id"])
    elif tool_name == "analyze_phishing":
        return run_analyze_phishing(tool_input["filepath"])
    elif tool_name == "analyze_iocs":
        return run_analyze_iocs(tool_input["iocs"])
    else:
        return f"Unknown tool: {tool_name}"

# ====================================================
# Local testing (Day 1 validation)
# ====================================================

if __name__ == "__main__":
    print(run_analyze_cve("CVE-2021-44228"))
    print(run_analyze_iocs(["45.33.32.156"]))
