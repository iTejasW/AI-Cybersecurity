# 01 — SSH Log Parser 🔍

A Python-based security tool that analyses Linux `auth.log` files to detect SSH brute force attempts and generates a structured analyst report.

---

## 🚨 The Problem

SSH brute force attacks are one of the most common attack vectors against Linux servers. Manually scanning through thousands of log lines to find suspicious IPs is slow and error-prone. This tool automates the entire detection and reporting process.

---

## ✅ What It Does

- Reads and parses Linux `auth.log` files line by line
- Detects failed SSH login attempts using regex
- Extracts IP addresses, usernames attempted, and timestamps
- Flags any IP with **5 or more failed attempts**
- Assigns a severity rating to each suspicious IP
- Generates a clean, structured report saved to a `.txt` file

---

## 🎯 Severity Ratings

| Failed Attempts | Severity |
|----------------|----------|
| 5 – 9 | `[MEDIUM]` |
| 10 – 19 | `[HIGH]` |
| 20+ | `[CRITICAL]` |

---

## 📁 Files

| File | Description |
|------|-------------|
| `ssh_log_parser.py` | Main parser script |
| `auth.log` | Sample log file for testing |
| `failed_login_report.txt` | Generated report (created on run) |

---

## ▶️ How to Run

**Requirements:** Python 3.x — no external libraries needed.

```bash
# Clone the repo
git clone https://github.com/iTejasW/AI-Cybersecurity.git
cd ai-security-portfolio/01-ssh-log-parser


# Run the parser
python ssh_log_parser.py
```

The report will be saved as `failed_login_report.txt` in the same folder.

---

## 📄 Sample Output

```
=== Suspicious Failed Login Report ===
Generated  : Dec 10 2024 06:30:00
Log file   : auth.log
Lines read : 72
Suspicious IPs found : 5
============================================================

[CRITICAL] Suspicious IP : 45.33.32.156
  Failed attempts : 22
  Usernames tried : admin, ansible, docker, ftp, git, hadoop, jenkins, kubernetes, mysql, postgres, root, test, ubuntu, vagrant
  First seen      : Dec 10 06:26:49
  Last seen       : Dec 10 06:27:23
------------------------------------------------------------

[HIGH] Suspicious IP : 192.168.1.105
  Failed attempts : 12
  Usernames tried : admin, deploy, guest, oracle, pi, root, test, ubuntu, user
  First seen      : Dec 10 06:25:43
  Last seen       : Dec 10 06:27:43
------------------------------------------------------------

[MEDIUM] Suspicious IP : 203.0.113.42
  Failed attempts : 5
  Usernames tried : admin, root, test
  First seen      : Dec 10 06:25:49
  Last seen       : Dec 10 06:26:19
------------------------------------------------------------
```

---

## 💡 Key Concepts Used

- **File I/O** — reading log files line by line
- **Regex** — extracting IPs, timestamps, and usernames with pattern matching
- **Dictionaries** — storing and grouping events per IP
- **Functions** — clean, reusable `get_severity()` logic
- **datetime module** — timestamping the generated report

---

## 🔮 Potential Improvements

- [ ] Accept log file path as a command-line argument
- [ ] Add geolocation lookup for flagged IPs (ip-api.com)
- [ ] Export report as JSON for SIEM ingestion
- [ ] Send email alert when CRITICAL IPs are detected
- [ ] Add support for other log formats (Windows Event Logs, Apache)

---

*Part of the [AI Security Portfolio](../README.md) — Project 01 of many.*
