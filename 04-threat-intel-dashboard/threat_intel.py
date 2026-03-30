from datetime import datetime
from dotenv import load_dotenv
from threat_intel_core import (
    detect_ioc_type,
    check_abuseipdb,
    check_virustotal,
    check_shodan,
    correlate_with_ai
)

load_dotenv()


# ====================================================
#              PROCESS ALL IOCs
# ====================================================

def process_iocs(file_path="iocs.txt"):
    with open(file_path, "r") as f:
        iocs = [line.strip() for line in f if line.strip()]

    results = []

    for ioc in iocs:
        ioc_type = detect_ioc_type(ioc)
        intel    = {}

        print(f"\n[+] Analyzing {ioc} ({ioc_type.upper()})...")

        if ioc_type == "ip":
            intel["abuseipdb"]  = check_abuseipdb(ioc)
            intel["virustotal"] = check_virustotal(ioc, ioc_type)
            intel["shodan"]     = check_shodan(ioc)

        elif ioc_type in ("domain", "hash"):
            intel["virustotal"] = check_virustotal(ioc, ioc_type)

        else:
            print(f"[-] Unknown IOC type for {ioc} — skipping")
            continue

        print("[+] Correlating with AI...")
        ai_verdict = correlate_with_ai(ioc, ioc_type, intel)

        results.append({
            "ioc":     ioc,
            "type":    ioc_type,
            "intel":   intel,
            "verdict": ai_verdict
        })

    generate_report(results)


# ====================================================
#              GENERATE REPORT
# ====================================================

def generate_report(results: list):
    timestamp    = datetime.now().strftime("%b %d %Y %H:%M:%S")
    report_lines = []

    report_lines.append("=" * 56)
    report_lines.append("   MORNING THREAT INTELLIGENCE BRIEFING")
    report_lines.append(f"   Generated: {timestamp}")
    report_lines.append("=" * 56)
    report_lines.append(f"IOCs Analyzed : {len(results)}")
    report_lines.append("")

    for r in results:
        report_lines.append("-" * 56)
        report_lines.append(f"IOC  : {r['ioc']}")
        report_lines.append(f"Type : {r['type'].upper()}")
        report_lines.append("-" * 56)
        report_lines.append(r["verdict"])
        report_lines.append("")

    report_lines.append("=" * 56)

    report = "\n".join(report_lines)
    print("\n" + report)

    filename = f"threat_briefing_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(filename, "w") as f:
        f.write(report)
    print(f"\n[+] Report saved to: {filename}")


# ====================================================
#              MAIN
# ====================================================

if __name__ == "__main__":
    print("\n========================================")
    print("   THREAT INTELLIGENCE DASHBOARD")
    print("========================================")
    process_iocs()
