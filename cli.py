import typer
import os
import subprocess
import sys
from dotenv import load_dotenv
import google.generativeai as genai
from datetime import datetime, timedelta
from openpyxl import Workbook, load_workbook
import os
import subprocess

app = typer.Typer(help="AI Git Guard CLI")

def install_hook():
    """
    Install AI Git Guard pre-push hook in the current Git repo.
    """
    hook_path = os.path.join(".git", "hooks", "pre-push")
    script = '''#!/bin/sh
echo "  AI Git Guard - Scanning for vulnerabilities..."
ai-git-guard scan
RESULT=$?
if [ $RESULT -ne 0 ]; then
  echo "  [BLOCKED] Push blocked due to security risks found by AI."
  exit 1
fi
'''
    try:
        with open(hook_path, "w") as f:
            f.write(script)
        os.chmod(hook_path, 0o755)
        print("[SUCCESS] Pre-push hook installed successfully.")
    except Exception as e:
        print(f"[ERROR] Failed to install hook: {e}")
        raise typer.Exit(code=1)

@app.command()
def install():
    """Install the pre-push hook."""
    install_hook()

@app.command()
def uninstall():
    """Remove or deactivate the AI Git Guard pre-push hook."""
    hook_path = os.path.join(".git", "hooks", "pre-push")
    
    if not os.path.exists(hook_path):
        print("No pre-push hook is currently installed.")
        raise typer.Exit(code=0)
    
    try:
        os.remove(hook_path)
        print("[SUCCESS] Pre-push hook removed successfully.")
    except Exception as e:
        print(f"[ERROR] Failed to remove hook: {e}")
        raise typer.Exit(code=1)

def log_to_excel(ai_result: str):
    """Append AI scan result to Excel log file with GitHub username and IST timestamp."""
    filename = "ai_git_guard_reports.xlsx"

    # Get GitHub username from git config
    try:
        github_username = subprocess.run(
            ["git", "config", "user.name"],
            capture_output=True,
            text=True,
            encoding="utf-8"
        ).stdout.strip() or "Unknown User"
    except Exception:
        github_username = "Unknown User"

    # Create workbook if it doesn’t exist
    if not os.path.exists(filename):
        wb = Workbook()
        ws = wb.active
        ws.title = "Reports"
        ws.append(["User", "Timestamp (IST)", "Severity", "Status", "Details", "Suggestions"])
        wb.save(filename)

    # Open existing workbook
    wb = load_workbook(filename)
    ws = wb.active

    # Extract fields from AI result
    severity, status, details, suggestions = "", "", "", ""
    prev_line = ""
    for line in ai_result.splitlines():
        if line.startswith("SEVERITY:"):
            severity = line.replace("SEVERITY:", "").strip()
        elif line.startswith("STATUS:"):
            status = line.replace("STATUS:", "").strip()
        elif line.startswith("DETAILS:"):
            details = line.replace("DETAILS:", "").strip()
        elif line.startswith("SUGGESTIONS:"):
            suggestions = line.replace("SUGGESTIONS:", "").strip()
        elif line.startswith("- "):
            if "DETAILS:" in prev_line:
                details += " " + line.strip("- ").strip()
            elif "SUGGESTIONS:" in prev_line:
                suggestions += " " + line.strip("- ").strip()
        prev_line = line

    # ✅ Get current time in IST (UTC + 5 hours 30 minutes)
    ist_time = datetime.utcnow() + timedelta(hours=5, minutes=30)
    timestamp = ist_time.strftime("%Y-%m-%d %H:%M:%S IST")

    # Append a new log entry
    ws.append([github_username, timestamp, severity, status, details, suggestions])
    wb.save(filename)

    print(f" Logged blocked push report to {filename}")
    print(f" User: {github_username} | 🕒 {timestamp}")

@app.command()
def scan():
    """Run AI security scan on committed code diff."""
    load_dotenv()
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

    if not GEMINI_API_KEY:
        print(" Gemini API key not found in .env file.")
        raise typer.Exit(code=1)

    genai.configure(api_key=GEMINI_API_KEY)

    diff = get_current_branch_diff()

    if not diff:
        print(" No committed changes to analyze.")
        raise typer.Exit(code=0)

    print("\n Running AI analysis on committed changes...\n")
    result = analyze_diff_with_ai(diff)

    if "SAFE TO RELEASE" in result.upper():
        print("Safe to release. Push allowed.")
        raise typer.Exit(code=0)
    else:
        print("Push blocked due to security risks found by AI.")
        log_to_excel(result)  # <-- log blocked report
        raise typer.Exit(code=1)


def get_current_branch_diff():
    # Get current branch
    result = subprocess.run(
    ['git', 'rev-parse', '--abbrev-ref', 'HEAD'],
    capture_output=True,
    text=True,
    encoding="utf-8"
    )
    current_branch = result.stdout.strip()

    # Get upstream branch
    upstream_result = subprocess.run(
        ['git', 'rev-parse', '--symbolic-full-name', '--abbrev-ref', f'{current_branch}@{{upstream}}'],
        capture_output=True,
        text=True,
        encoding="utf-8"
    )

    if upstream_result.returncode != 0:
        print(f"⚠️ No upstream set for branch '{current_branch}'. Please set upstream with:")
        print(f"   git push --set-upstream origin {current_branch}")
        return ""

    upstream = upstream_result.stdout.strip()

    # Get diff between current branch and upstream
    diff_result = subprocess.run(
        ['git', 'diff', f'{upstream}...{current_branch}', '--unified=0'],
        capture_output=True,
        text=True,
        encoding="utf-8"
    )
    return diff_result.stdout.strip()

def analyze_diff_with_ai(diff: str) -> str:
    prompt = f"""
You are a senior security reviewer. A developer is trying to push the following code changes:

{diff}

Your job is to:
1. Identify security vulnerabilities (especially OWASP Top 10)
2. Focus ONLY on OWASP top 10 vulnerabilities such as the following critical issues:
   - Code injection
   - Command injection
   - SQL injection (unparameterized queries)
   - Hardcoded secrets or API keys
   - Dangerous file operations (e.g., write to arbitrary paths, permission changes)
   - Critical deserialization vulnerabilities

Ignore minor issues like input length limits, minor validation gaps, or generic best practices unless they clearly lead to immediate risk.

3. Provide a result using **only this exact format**:

---
SEVERITY: [None | Low | Medium | High]  
STATUS: [SAFE TO RELEASE | NEEDS REVIEW - Potential issues: (summary)]  
DETAILS:
- [brief explanation of any found issues, with file/line if possible]
SUGGESTIONS:
- [fix or safer approach]
---

If no issue is found, return:

---
SEVERITY: None  
STATUS: SAFE TO RELEASE  
---
"""

    model = genai.GenerativeModel("gemini-2.0-flash")

    try:
        response = model.generate_content(prompt)
        result = getattr(response, "text", "").strip()

        print("\n AI Security Analysis Report:\n")
        print(result)
        return result
    except Exception as e:
        print("Gemini API Error:", e)
        return "NEEDS REVIEW - AI check failed"

def main():
    app()

if __name__ == "__main__":
    main()
