# agent.py
# The AI Security Agent — main ReAct orchestration loop

import os
import json
import anthropic
from dotenv import load_dotenv
from agent_tools import TOOL_DEFINITIONS, execute_tool

# Load environment variables
load_dotenv()

# Initialize Claude client
client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

# System prompt defining agent behavior
SYSTEM_PROMPT = """You are an expert AI security analyst with access to specialized tools.

When a user asks you to investigate something, use your tools proactively:
- CVE IDs → use analyze_cve
- Email files (.eml paths) → use analyze_phishing
- IPs, domains, or hashes → use analyze_iocs
- If an analysis surfaces suspicious IPs, automatically check them with analyze_iocs

Always structure your final response with:
1. VERDICT — one-line summary (MALICIOUS / SUSPICIOUS / CLEAN / CRITICAL)
2. FINDINGS — what the tools discovered
3. ACTIONS — concrete next steps for the analyst

Strategic Guidance:
- When analyzing CVEs, prioritize those with high EPSS scores (> 10%) as they have a higher probability of active exploitation.
- Use AlienVault OTX 'Pulses' and 'Tags' to identify if an IOC is associated with specific threat actors or ongoing campaigns.

Be direct. Lead with severity. Skip filler phrases.
"""


def run_agent(user_message: str, history: list) -> tuple[str, list]:
    """
    Core agent loop. Runs until Claude stops requesting tools.

    Args:
        user_message: User input
        history: Conversation history

    Returns:
        (final_response_text, updated_history)
    """
    # Add user message to history
    history.append({"role": "user", "content": user_message})

    # ReAct loop
    while True:
        response = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=4096,
            system=SYSTEM_PROMPT,
            tools=TOOL_DEFINITIONS,
            messages=history
        )

        # Case 1: Final answer
        if response.stop_reason == "end_turn":
            final_text = next(
                (block.text for block in response.content if hasattr(block, "text")),
                "No response generated."
            )
            history.append({"role": "assistant", "content": response.content})
            return final_text, history

        # Case 2: Tool usage requested
        elif response.stop_reason == "tool_use":
            # Save Claude's tool request
            history.append({"role": "assistant", "content": response.content})

            tool_results = []

            for block in response.content:
                if block.type != "tool_use":
                    continue

                print(f"→ Calling: {block.name}")
                print(f"    Args:    {json.dumps(block.input)}")

                result_text = execute_tool(block.name, block.input)

                print(f"    Done.    {len(result_text)} chars returned")

                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": result_text
                })

            # Send tool results back to Claude as user message
            history.append({"role": "user", "content": tool_results})

        else:
            return f"Unexpected stop reason: {response.stop_reason}", history


def main():
    """Simple REPL interface."""
    print("╔══════════════════════════════════╗")
    print("║   AI Security Agent  v1.0        ║")
    print("║   Tools: CVE · Phishing · Intel  ║")
    print("╚══════════════════════════════════╝")
    print("Type 'exit' to quit, 'clear' to reset history")

    history = []

    while True:
        try:
            user_input = input("You: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("Shutting down.")
            break

        if not user_input:
            continue
        if user_input.lower() == "exit":
            print("Shutting down.")
            break
        if user_input.lower() == "clear":
            history = []
            print("History cleared.")
            continue

        print("Agent: thinking...")

        response_text, history = run_agent(user_input, history)

        print(f"Agent:{'-' * 60}")
        print(response_text)
        print('-' * 60 + "")


if __name__ == "__main__":
    main()
