import sys
import os
import re
import time
import logging
from datetime import datetime, timedelta

# --- 1. CONFIGURATION & PATHING ---
# Ensure we can find the agent in Project 05
PROJECT_05_DIR = os.path.join(os.path.dirname(__file__), '..', '05-security-agent')
sys.path.append(PROJECT_05_DIR)

from agent import run_agent

# Logging Setup
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler("hunter.log"), logging.StreamHandler()]
)

class HunterConfig:
    """Centralized settings for the Autonomous Hunter."""
    LOG_FILE = os.path.join(os.path.dirname(__file__), '..', '01-ssh-log-parser', 'auth.log')
    THRESHOLD = 15
    WINDOW_MINUTES = 10
    COOLDOWN_HOURS = 1  # Don't re-investigate the same IP too often
    FAILED_LOGIN_REGEX = re.compile(
        r"(\w{3}\s+\d+\s\d{2}:\d{2}:\d{2}).*Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)"
    )

# --- 2. THREAT ENGINE ---

class ThreatEngine:
    """Handles the sliding window logic and state for suspicious IPs."""
    def __init__(self):
        self.ip_tracker = {}        # IP -> [timestamps]
        self.agent_memories = {}    # IP -> [conversation history]
        self.last_investigation = {} # IP -> last_investigation_time

    def is_within_cooldown(self, ip):
        """Prevents duplicate AI calls for the same IP within the cooldown period."""
        last_time = self.last_investigation.get(ip)
        if last_time and datetime.now() - last_time < timedelta(hours=HunterConfig.COOLDOWN_HOURS):
            return True
        return False

    def check_threshold(self, ip):
        """Sliding window check to see if an IP has crossed the attack threshold."""
        now = datetime.now()
        
        # Prune old entries
        attempts = self.ip_tracker.get(ip, [])
        valid_attempts = [t for t in attempts if now - t <= timedelta(minutes=HunterConfig.WINDOW_MINUTES)]
        
        valid_attempts.append(now)
        self.ip_tracker[ip] = valid_attempts
        
        return len(valid_attempts) >= HunterConfig.THRESHOLD

# --- 3. MAIN ORCHESTRATOR ---

class HunterOrchestrator:
    """The 'Brain' that tails logs and commands the AI Agent."""
    def __init__(self):
        self.config = HunterConfig()
        self.engine = ThreatEngine()

    def tail_log(self):
        """Generator that yields new lines from the log file in real-time."""
        try:
            with open(self.config.LOG_FILE, "r") as f:
                f.seek(0, os.SEEK_END)
                while True:
                    line = f.readline()
                    if not line:
                        time.sleep(0.1)
                        continue
                    yield line
        except FileNotFoundError:
            logging.error(f"Target log file not found: {self.config.LOG_FILE}")
            sys.exit(1)

    def trigger_ai_agent(self, ip, username):
        """Prepares context and initiates the AI investigation."""
        if self.engine.is_within_cooldown(ip):
            logging.info(f"Skipping investigation for {ip} (Cooldown Active).")
            return

        logging.info(f"🚀 THRESHOLD EXCEEDED: {ip}. Invoking AI Agent...")
        
        # Manage AI Memory (History)
        history = self.engine.agent_memories.get(ip, [])
        
        prompt = (
            f"AUTONOMOUS ALERT: High-velocity brute force detected from IP: {ip}. "
            f"Last attempted username: '{username}'. "
            f"Analyze this IOC and provide a security verdict and remediation plan."
        )

        # Call the Agent from Project 05
        response_text, updated_history = run_agent(prompt, history)
        
        # Update State
        self.engine.agent_memories[ip] = updated_history
        self.engine.last_investigation[ip] = datetime.now()
        self.engine.ip_tracker[ip] = [] # Reset tracker after trigger

        # Output & Save
        self.save_report(ip, response_text)

    def save_report(self, ip, report):
        filename = f"incident_{ip.replace('.', '_')}.txt"
        with open(filename, "w") as f:
            f.write(report)
        logging.info(f"✅ Investigation complete for {ip}. Report: {filename}")

    def run(self):
        logging.info(f"🕵️ Hunter started. Monitoring {self.config.LOG_FILE}...")
        for line in self.tail_log():
            match = self.config.FAILED_LOGIN_REGEX.search(line)
            if match:
                _, username, ip = match.groups()
                if self.engine.check_threshold(ip):
                    self.trigger_ai_agent(ip, username)

if __name__ == "__main__":
    orchestrator = HunterOrchestrator()
    orchestrator.run()