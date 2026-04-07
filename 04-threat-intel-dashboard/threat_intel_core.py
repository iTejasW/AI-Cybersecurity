import time
import os
import re
import requests
from OTXv2 import OTXv2, IndicatorTypes
from dotenv import load_dotenv
from anthropic import Anthropic

load_dotenv()
client = Anthropic()


#Instead of calling requests.get() directly in every function, we will create a "Wrapper" function that handles the retries automatically.
def safe_request(url, headers=None, params=None, retries=3, backoff_factor=2, timeout=10):
     """Makes an API request with exponential backoff for rate limits."""
    for i in range(retries):
        response = requests.get(url, headers=headers, params=params, timeout=timeout)
            if response.status_code == 200:
                return response.json()
            
            # 429 is the standard code for "Too Many Requests"
            if response.status_code == 429:
                wait_time = backoff_factor ** i
                print(f"[!] Rate limited. Retrying in {wait_time}s...")
                time.sleep(wait_time)
                continue
                
            return {"error": f"HTTP {response.status_code}"}
            
        except Exception as e:
            if i == retries - 1:
                return {"error": str(e)}
            time.sleep(backoff_factor ** i)
    return {"error": "Max retries exceeded"}

# ====================================================
#              IOC TYPE DETECTION
# ====================================================

def detect_ioc_type(ioc: str) -> str:
    ip_pattern     = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$")
    hash_pattern   = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")
    domain_pattern = re.compile(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$")
    cve_pattern = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)

    if ip_pattern.match(ioc):
        return "ip"
    elif hash_pattern.match(ioc):
        return "hash"
    elif domain_pattern.match(ioc):
        return "domain"
    elif cve_pattern.match(ioc): 
        return "cve"
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
        data = safe_request(url, headers=headers, params=params, timeout=10)

        if data.status_code != 200:
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
        data = safe_request(endpoints[ioc_type], headers=headers, timeout=10)

        if data.status_code != 200:
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
        data = safe_request(
            f"https://api.shodan.io/shodan/host/{ip}",
            params={"key": API_KEY},
            timeout=10
        )

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
#              Alienvault OTX check
# ====================================================

def check_otx(ioc: str, ioc_type: str) -> dict:
    API_KEY = os.getenv("OTX_API_KEY")
    if not API_KEY:
        return {"error": "OTX API Key missing"}

    otx = OTXv2(API_KEY)
    
    # Map your types to OTX IndicatorTypes
    otx_type = {
        "ip": IndicatorTypes.IPv4,
        "domain": IndicatorTypes.DOMAIN,
        "hash": IndicatorTypes.FILE # OTX handles MD5/SHA automatically
    }.get(ioc_type)

    try:
        # Get general reputation and pulse information
        results = otx.get_indicator_details_full(otx_type, ioc)
        pulses = results.get('general', {}).get('pulses', [])
        
        return {
            "pulse_count": len(pulses),
            "threat_names": [p['name'] for p in pulses[:3]], # Get top 3 campaign names
            "tags": list(set([tag for p in pulses for tag in p.get('tags', [])]))[:5] # Top 5 tags
        }
    except Exception as e:
        return {"error": str(e)}
    
# ====================================================
#              EPSS Score
# ====================================================
def get_epss_score(cve_id: str) -> dict:
    """Fetches the EPSS score for a given CVE from FIRST.org."""
    url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
    
    try:
        response = safe_request(url, timeout=10)
        if response.status_code == 200:
            data = response.get("data", [])
            if data:
                # EPSS is returned as a decimal (0.01 = 1%)
                # We convert it to a percentage for easier AI reasoning
                epss_value = float(data[0].get("epss", 0))
                percent = f"{epss_value * 100:.2f}%"
                return {"epss": percent, "percentile": data[0].get("percentile")}
        return {"error": "No EPSS data found"}
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
        # Inside threat_intel_core.py -> correlate_with_ai()
    if "otx" in intel:
        o = intel["otx"]
        sources_summary += f"""
AlienVault OTX:
  Pulses Found : {o.get('pulse_count')}
  Active Threats: {", ".join(o.get('threat_names', []))}
  Tags         : {", ".join(o.get('tags', []))}
"""
        # Inside threat_intel_core.py -> correlate_with_ai()
    if "epss" in intel:
        e = intel["epss"]
        sources_summary += f"""
Exploit Prediction (EPSS):
  Probability of Exploitation: {e.get('epss')}
  Percentile: {e.get('percentile')} (Higher means more likely to be attacked)
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
