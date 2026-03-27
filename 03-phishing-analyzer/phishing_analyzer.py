import email
import re
from anthropic import Anthropic
from dotenv import load_dotenv

# ====================================================
#                   EMAIL PARSER
# ====================================================
def parse_email(filepath):
    with open(filepath, "r", encoding="utf-8") as f:
        raw = f.read()

    msg = email.message_from_string(raw)

    sender = msg.get("From", "")
    reply_to = msg.get("Reply-To", "")
    subject = msg.get("Subject", "")

    # -------- Extract body --------
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                payload = part.get_payload(decode=True)
                if payload:
                    body += payload.decode(errors="ignore")
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            body = payload.decode(errors="ignore")
        else:
            body = msg.get_payload()

    body = body.strip()

    # -------- Extract URLs --------
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    urls = re.findall(url_pattern, body)

    return {
        "sender": sender,
        "reply_to": reply_to,
        "subject": subject,
        "body": body,
        "urls": urls
    }


# ====================================================
#           STATIC INDICATOR EXTRACTION
# ====================================================
def extract_indicators(parsed_email):
    indicators = []

    sender    = parsed_email["sender"]   or ""
    reply_to  = parsed_email["reply_to"] or ""
    subject   = parsed_email["subject"]  or ""
    body      = parsed_email["body"]     or ""
    urls      = parsed_email["urls"]

    # 1. Reply-To domain mismatch
    sender_domain  = sender.split("@")[-1].replace(">", "").strip() if "@" in sender else ""
    replyto_domain = reply_to.split("@")[-1].replace(">", "").strip() if reply_to and "@" in reply_to else ""

    if reply_to and sender_domain != replyto_domain:
        indicators.append("Reply-To domain differs from sender domain")

    # 2. Urgency language
    urgency_words = [
        "urgent", "immediately", "suspended", "verify", "limited",
        "expires", "within 24", "act now", "click here"
    ]
    for word in urgency_words:
        if word.lower() in subject.lower() or word.lower() in body.lower():
            indicators.append(f"Urgency language detected: '{word}'")
            break

    # 3. Suspicious TLDs in URLs
    suspicious_tlds = [".ru", ".tk", ".xyz", ".top", ".click", ".link"]
    for url in urls:
        for tld in suspicious_tlds:
            if tld in url:
                indicators.append(f"Suspicious URL TLD detected: {url}")

    # 4. High number of URLs
    if len(urls) >= 3:
        indicators.append(f"High number of URLs: {len(urls)}")

    # 5. Display name mismatch
    if "<" in sender and ">" in sender:
        display = sender.split("<")[0].strip().lower()
        domain  = sender_domain.lower()
        if display and domain and display not in domain and domain not in display:
            indicators.append("Display name may not match sender domain")

    return indicators


# ====================================================
#               AI PHISHING ANALYSIS
# ====================================================
load_dotenv()
client = Anthropic()

def analyze_with_ai(parsed_email, indicators):
    prompt = f"""
You are a senior SOC analyst specializing in phishing detection.
Analyze this email and provide a structured verdict.

EMAIL DATA:
Sender     : {parsed_email['sender']}
Reply-To   : {parsed_email['reply_to']}
Subject    : {parsed_email['subject']}
URLs Found : {len(parsed_email['urls'])}
URL List   : {', '.join(parsed_email['urls']) if parsed_email['urls'] else 'None'}

PRE-DETECTED INDICATORS:
{chr(10).join(f'- {i}' for i in indicators) if indicators else 'None detected'}

EMAIL BODY:
{parsed_email['body'][:1000]}

Respond EXACTLY in this format:

VERDICT: [PHISHING / SUSPICIOUS / LEGITIMATE]
CONFIDENCE: [0-100]%
RISK LEVEL: [HIGH / MEDIUM / LOW]

INDICATORS FOUND:
List every phishing indicator you can identify, one per line starting with -

RECOMMENDED ACTION:
Specific steps for the SOC analyst to take right now.

EXPLANATION:
2-3 sentences explaining your verdict.
"""

    message = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=1000,
        messages=[{"role": "user", "content": prompt}]
    )

    return message.content[0].text


# ====================================================
#                       MAIN
# ====================================================
def main():
    print("\n========================================")
    print("     PHISHING EMAIL ANALYZER")
    print("========================================")

    filepath = input("\nEnter path to .eml file: ").strip()

    print("\n[+] Parsing email...")
    parsed = parse_email(filepath)

    print(f"[+] Sender  : {parsed['sender']}")
    print(f"[+] Subject : {parsed['subject']}")
    print(f"[+] URLs    : {len(parsed['urls'])} found")

    print("[+] Extracting indicators...")
    indicators = extract_indicators(parsed)
    print(f"[+] {len(indicators)} indicators detected")

    print("[+] Running AI analysis...")
    verdict = analyze_with_ai(parsed, indicators)

    output = f"""
========================================
   PHISHING ANALYSIS REPORT
========================================
Subject  : {parsed['subject']}
Sender   : {parsed['sender']}
Reply-To : {parsed['reply_to']}
URLs     : {len(parsed['urls'])} found
----------------------------------------
{verdict}
========================================
"""

    print(output)

    filename = "phishing_report.txt"
    with open(filename, "w") as f:
        f.write(output)
    print(f"[+] Report saved to: {filename}")


if __name__ == "__main__":
    main()
