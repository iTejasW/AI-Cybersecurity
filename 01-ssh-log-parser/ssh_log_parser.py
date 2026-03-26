import re
from datetime import datetime

logfile = "auth.log"
report_file = "failed_login_report.txt"

# ── Regex Patterns ────────────────────────────────────────────────────────────

# Valid IPv4 (0–255 only)
ip_pattern = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)

# Timestamp: e.g. "Dec 10 06:25:43"
timestamp_pattern = re.compile(
    r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"
)

# Username: captures word between "for [invalid user] X from"
username_pattern = re.compile(r"for (?:invalid user )?(\w+) from")


# ── Severity Rating ───────────────────────────────────────────────────────────

def get_severity(count):
    if 5 <= count <= 9:
        return "[MEDIUM]"
    elif 10 <= count <= 19:
        return "[HIGH]"
    else:
        return "[CRITICAL]"


# ── Read & Parse Log ──────────────────────────────────────────────────────────

# Dictionary: IP -> list of (timestamp, username)
failed_attempts = {}
total_lines = 0

with open(logfile, "r") as f:
    for line in f:
        total_lines += 1
        if "failed password" in line.lower():
            timestamp_match = timestamp_pattern.search(line)
            ip_match        = ip_pattern.search(line)
            username_match  = username_pattern.search(line)

            if timestamp_match and ip_match and username_match:
                timestamp = timestamp_match.group()
                ip        = ip_match.group()
                username  = username_match.group(1)

                failed_attempts.setdefault(ip, []).append((timestamp, username))


# ── Write Report ──────────────────────────────────────────────────────────────

suspicious_count = 0

with open(report_file, "w") as rpt:

    # Summary block
    rpt.write("=== Suspicious Failed Login Report ===\n")
    rpt.write(f"Generated  : {datetime.now().strftime('%b %d %Y %H:%M:%S')}\n")
    rpt.write(f"Log file   : {logfile}\n")
    rpt.write(f"Lines read : {total_lines}\n")

    # Count suspicious IPs first for the summary
    suspicious_ips = {ip: events for ip, events in failed_attempts.items() if len(events) >= 5}
    rpt.write(f"Suspicious IPs found : {len(suspicious_ips)}\n")
    rpt.write("=" * 60 + "\n\n")

    # Per-IP detail
    for ip, events in suspicious_ips.items():
        suspicious_count += 1
        count      = len(events)
        severity   = get_severity(count)
        first_seen = events[0][0]
        last_seen  = events[-1][0]
        usernames  = sorted(set(u for _, u in events))

        rpt.write(f"{severity} Suspicious IP : {ip}\n")
        rpt.write(f"  Failed attempts : {count}\n")
        rpt.write(f"  Usernames tried : {', '.join(usernames)}\n")
        rpt.write(f"  First seen      : {first_seen}\n")
        rpt.write(f"  Last seen       : {last_seen}\n")
        rpt.write("-" * 60 + "\n\n")

    rpt.write(f"Total suspicious IPs : {suspicious_count}\n")

print(f"[+] Report saved to: {report_file}")
