import os
import re
import requests
from dotenv import load_dotenv
from anthropic import Anthropic

load_dotenv()
client = Anthropic()


# ====================================================
#              IOC TYPE DETECTION
# ====================================================

def detect_ioc_type(ioc: str) -> str:
    ip_pattern     = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$")
    hash_pattern   = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")
    domain_pattern = re.compile(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$")

    if ip_pattern.match(ioc):
        return "ip"
    elif hash_pattern.match(ioc):
        return "hash"
    elif domain_pattern.match(ioc):
        return "domain"
    else:
        return "unknown"


# ====================================================
#              ABUSEIPDB CHECK
# ====================================================

def check_abuseipdb(ip: str) -> dict:
    url     = "https://api.abuseipdb.com/api/v2/check"
    API_KEY = os.getenv("ABUSEIPDB_API_KEY")

    headers = {"Key": API_KEY, "Accept": "application/json"}
    params  = {"ipAddress": ip, "maxAgeInDays": 90}

    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        data     = response.json()

        if response.status_code != 200:
            return {"error": data.get("message", "Unknown error")}

        result = data["data"]
        return {
            "abuseConfidenceScore": result.get("abuseConfidenceScore"),
            "totalReports":         result.get("totalReports"),
            "countryCode":          result.get("countryCode"),
            "isp":                  result.get("isp"),
        }

    except Exception as e:
        return {"error": str(e)}


# ====================================================
#              VIRUSTOTAL CHECK
# ====================================================

def check_virustotal(ioc: str, ioc_type: str) -> dict:
    API_KEY   = os.getenv("VIRUSTOTAL_API_KEY")
    headers   = {"x-apikey": API_KEY}
    endpoints = {
        "ip":     f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}",
        "domain": f"https://www.virustotal.com/api/v3/domains/{ioc}",
        "hash":   f"https://www.virustotal.com/api/v3/files/{ioc}"
    }

    if ioc_type not in endpoints:
        return {"error": "Unsupported IOC type for VirusTotal"}

    try:
        response = requests.get(endpoints[ioc_type], headers=headers, timeout=10)
        data     = response.json()

        if response.status_code != 200:
            return {"error": data.get("error", {}).get("message", "Unknown error")}

        stats = data["data"]["attributes"]["last_analysis_stats"]
        return {
            "malicious":  stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless":   stats.get("harmless", 0),
            "total":      sum(stats.values())
        }

    except Exception as e:
        return {"error": str(e)}


# ====================================================
#              SHODAN CHECK
# ====================================================

def check_shodan(ip: str) -> dict:
    API_KEY = os.getenv("SHODAN_API_KEY")

    try:
        response = requests.get(
            f"https://api.shodan.io/shodan/host/{ip}",
            params={"key": API_KEY},
            timeout=10
        )
        data = response.json()

        if "error" in data:
            return {"error": data["error"]}

        return {
            "open_ports": data.get("ports", []),
            "country":    data.get("country_name", "Unknown"),
            "org":        data.get("org", "Unknown"),
            "os":         data.get("os", "Unknown"),
            "hostnames":  data.get("hostnames", [])
        }

    except Exception as e:
        return {"error": str(e)}


# ====================================================
#              AI CORRELATION
# ====================================================

def correlate_with_ai(ioc: str, ioc_type: str, intel: dict) -> str:
    sources_summary = ""

    if "abuseipdb" in intel:
        a = intel["abuseipdb"]
        sources_summary += f"""
AbuseIPDB:
  Abuse Score  : {a.get('abuseConfidenceScore')}/100
  Total Reports: {a.get('totalReports')}
  Country      : {a.get('countryCode')}
  ISP          : {a.get('isp')}
"""

    if "virustotal" in intel:
        v = intel["virustotal"]
        sources_summary += f"""
VirusTotal:
  Malicious    : {v.get('malicious')}/{v.get('total')} engines
  Suspicious   : {v.get('suspicious')}/{v.get('total')} engines
"""

    if "shodan" in intel:
        s = intel["shodan"]
        sources_summary += f"""
Shodan:
  Open Ports   : {s.get('open_ports')}
  Organization : {s.get('org')}
  Country      : {s.get('country')}
  Hostnames    : {s.get('hostnames')}
"""

    prompt = f"""
You are a senior threat intelligence analyst.
Analyze the following IOC data from multiple sources and provide a verdict.

IOC        : {ioc}
IOC Type   : {ioc_type.upper()}

INTELLIGENCE DATA:
{sources_summary}

Respond EXACTLY in this format:

VERDICT: [MALICIOUS / SUSPICIOUS / CLEAN / UNKNOWN]
RISK LEVEL: [CRITICAL / HIGH / MEDIUM / LOW]
CONFIDENCE: [0-100]%

ANALYSIS:
2-3 sentences correlating findings across all sources.

RECOMMENDED ACTION:
Specific immediate action for the security team.
"""

    message = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=500,
        messages=[{"role": "user", "content": prompt}]
    )

    return message.content[0].text
