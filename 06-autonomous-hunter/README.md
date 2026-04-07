```markdown
# 🛡️ Autonomous AI Threat Hunter (Stateful XDR Orchestrator)

An intelligent, real-time Security Orchestration, Automation, and Response (SOAR) system. This project acts as an autonomous Tier 1/Tier 2 SOC analyst, actively tailing server logs to detect brute-force attacks, and orchestrating an AI agent to investigate, escalate, and report on the threats.

## 📖 Overview

Traditional security scripts trigger static alerts on single events, leading to massive alert fatigue. The **Autonomous AI Threat Hunter** solves this by implementing a **Sliding Window Detection Engine** and a **Stateful AI Orchestrator**. 

It doesn't just alert; it investigates. When an attack crosses a specific threshold, the orchestrator triggers an AI agent (Claude/LLM) equipped with threat intelligence tools to analyze the IOC (Indicator of Compromise), synthesize a verdict, and generate an actionable remediation report.

## ✨ Key Features

* **Real-Time Log Streaming (`tail -f` logic):** Efficiently monitors Linux `auth.log` in real-time using non-blocking file seeking, minimizing CPU overhead.
* **Sliding Window Threshold Detection:** Prevents noise by only triggering when an attacker hits `X` failed attempts within `Y` minutes (e.g., 15 attempts in 10 minutes). Old attempts are continuously pruned from memory.
* **Stateful Agent Memory:** Maintains a continuous "case file" (`agent_memories`) for each malicious IP in RAM. If an attacker returns, the AI is fed its previous investigation context, allowing it to escalate threats dynamically.
* **Intelligent Cooldown Mechanism:** Prevents API token exhaustion by enforcing a strict cooldown period (e.g., 1 hour) per IP. Subsequent attacks within this window are logged but do not re-trigger expensive AI API calls.
* **Automated Analyst Reporting:** Automatically generates and saves structured `.txt` incident reports containing the AI's verdict and recommended remediation steps.

---

## 🏗️ System Architecture

The codebase is organized into three distinct, object-oriented layers:

### 1. Configuration (`HunterConfig`)
Centralizes all tunable parameters.
* **Threshold Settings:** Defines the sliding window variables (`THRESHOLD = 15`, `WINDOW_MINUTES = 10`).
* **Regex Engine:** Uses compiled regular expressions to parse standard SSH `auth.log` formats to extract the Timestamp, Username, and Source IP.

### 2. Threat Engine (`ThreatEngine`)
The mathematical brain of the operation.
* **`ip_tracker`:** A dictionary mapping IPs to lists of attack timestamps. Handles the pruning of expired events to maintain the sliding window.
* **`check_threshold()`:** Evaluates if a specific IP has crossed the danger threshold within the active time window.
* **Cooldown Management:** Validates if an IP is eligible for a new AI investigation or if it is currently muted to save resources.

### 3. Orchestrator (`HunterOrchestrator`)
The operational bridge between the raw logs and the AI.
* **`tail_log()`:** A Python generator that yields new lines as they are written to disk by the OS.
* **`trigger_ai_agent()`:** Packages the contextual prompt, fetches the historical memory for that specific IP, and invokes the external AI agent script. Stores the returned context back into the Threat Engine's memory map.

---

## 🚀 Setup & Installation

### Prerequisites
This orchestrator relies on the presence of related micro-projects (specifically the log source and the AI agent). Ensure your directory structure looks like this:

```text
your-repo-root/
├── 01-ssh-log-parser/
│   └── auth.log             <-- The target log file being monitored
├── 05-security-agent/
│   ├── agent.py             <-- The AI Agent script (ReAct logic)
│   └── .env                 <-- API keys for the AI and Threat Intel tools
└── 06-autonomous-hunter/
    └── hunter_orchestrator.py <-- THIS script
```

### Execution
1. Navigate to the project directory:
   ```bash
   cd 06-autonomous-hunter
   ```
2. Run the orchestrator:
   ```bash
   python hunter_orchestrator.py
   ```

---

## 🧪 Simulating an Attack

To test the orchestrator without exposing your server to the internet, you can simulate a brute-force attack by injecting dummy logs into your `auth.log` file.

Open a separate terminal and run:

**Linux/macOS:**
```bash
for i in {1..20}; do 
  echo "Apr 07 23:00:01 server sshd: Failed password for root from 203.0.113.50 port 54321" >> ../01-ssh-log-parser/auth.log
  sleep 0.1
done
```

**What happens next?**
1. The script will ingest the lines in real-time.
2. On the 15th line, the threshold is breached.
3. The AI agent is triggered, querying threat intel for `203.0.113.50`.
4. An `incident_203_0_113_50.txt` report is generated in your directory.

---

## 📊 Example Console Output

```text
2024-11-20 14:00:05 [INFO] 🕵️ Hunter started. Monitoring ../01-ssh-log-parser/auth.log...
2024-11-20 14:05:22 [INFO] 🚀 THRESHOLD EXCEEDED: 203.0.113.50. Invoking AI Agent...
2024-11-20 14:05:40 [INFO] ✅ Investigation complete for 203.0.113.50. Report: incident_203_0_113_50.txt
2024-11-20 14:10:15 [INFO] Skipping investigation for 203.0.113.50 (Cooldown Active).
```

---

## 🛠️ Future Enhancements
* **Active Mitigation:** Integrate local OS commands (e.g., `os.system("iptables -A INPUT -s {ip} -j DROP")`) to allow the AI to autonomously block confirmed threats.
* **Persistent State DB:** Transition `agent_memories` and `ip_tracker` from Volatile RAM (Python Dictionaries) to a local SQLite/Redis database so memory persists across script restarts.
* **Multi-Log Support:** Extend the `HunterConfig` to tail an array of log files (e.g., Nginx `access.log`, Fail2Ban logs) simultaneously using asynchronous I/O (`asyncio`).
```
