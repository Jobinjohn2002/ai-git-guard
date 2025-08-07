# ai_prepush_check.py
import subprocess
import os
import re
import sys
from dotenv import load_dotenv
import google.generativeai as genai

load_dotenv()
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

if not GEMINI_API_KEY:
    print("Gemini API key not found in .env file.")
    sys.exit(1)

genai.configure(api_key=GEMINI_API_KEY)

def get_staged_diff():
    try:
        result = subprocess.run(['git', 'diff', '--cached'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result.stdout.decode().strip()
    except Exception as e:
        print("Error getting staged diff:", e)
        return ""

def analyze_diff_with_ai(diff: str) -> str:
    prompt = f"""
    Analyze the following git diff for security risks.

    Your job:
    - Identify OWASP Top 10 vulnerabilities (e.g. XSS, SQL Injection, etc.)
    - Check for hardcoded secrets, API keys, tokens
    - Identify risky functions (eval, exec, system, raw SQL)

    Git Diff:
    {diff}

    Respond only with:
    - "SAFE TO RELEASE"
    - OR "NEEDS REVIEW - Potential issues: [list the problems]"

    Be concise. Explain only if there's an issue.
    """

    model = genai.GenerativeModel("gemini-1.5-flash")
    try:
        response = model.generate_content(prompt)
        return response.text.strip()
    except Exception as e:
        print("Gemini API error:", e)
        return "NEEDS REVIEW - AI check failed"

def main():
    diff = get_staged_diff()
    if not diff:
        print("No staged changes to analyze.")
        return 0

    print("🔍 Running AI analysis on staged changes...")
    decision = analyze_diff_with_ai(diff)

    print("\nAI Response:\n" + decision)

    if "SAFE TO RELEASE" in decision.upper():
        return 0
    return 1

if __name__ == "__main__":
    sys.exit(main())
