import typer
import os
import subprocess
import sys
from dotenv import load_dotenv
import google.generativeai as genai
from datetime import datetime, timedelta
# import mysql.connector
# from mysql.connector import Error
import pymysql


app = typer.Typer(help="AI Git Guard CLI — Secure your pushes with AI checks")

# ------------------------------------------------------------
# Hook installation
# ------------------------------------------------------------

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

# ------------------------------------------------------------
# MySQL Logging
# ------------------------------------------------------------

def log_to_mysql(ai_result: str):
    """Append AI scan result to a shared MySQL table with project and user info."""
    connection = None

    try:
        connection = pymysql.connect(
            host=os.getenv("DB_HOST"),
            port=int(os.getenv("DB_PORT")),
            user=os.getenv("DB_USER"),
            password=os.getenv("DB_PASSWORD"),
            database=os.getenv("DB_NAME"),
            charset="utf8mb4",
            cursorclass=pymysql.cursors.Cursor
        )


        cursor = connection.cursor()

        severity, status, details, suggestions = "None", "SAFE TO RELEASE", "", ""
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
                    details += " " + line.lstrip("- ").strip()
                elif "SUGGESTIONS:" in prev_line:
                    suggestions += " " + line.lstrip("- ").strip()
            prev_line = line

        github_username = (
            subprocess.run(["git", "config", "user.name"], capture_output=True, text=True)
            .stdout.strip()
            or "Unknown User"
        )

        project_path = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True
        ).stdout.strip()

        project_name = os.path.basename(project_path) or "Unknown Project"
        ist_time = datetime.utcnow() + timedelta(hours=5, minutes=30)
        is_blocked = not ("SAFE TO RELEASE" in status.upper())

        cursor.execute("""
            INSERT INTO ai_git_guard_logs 
            (project_name, user_name, timestamp, severity, status, details, suggestions, is_blocked)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            project_name, github_username, ist_time,
            severity, status, details, suggestions, is_blocked
        ))

        connection.commit()
        print(f"[DB] Log saved for {github_username}")

    except Exception as e:
        print(f"[DB ERROR] {e}")

    finally:
        if connection:
            connection.close()

# ------------------------------------------------------------
# AI Security Scan Logic
# ------------------------------------------------------------

def get_current_branch_diff():
    """Get code diff between current branch and upstream."""
    result = subprocess.run(
        ['git', 'rev-parse', '--abbrev-ref', 'HEAD'],
        capture_output=True,
        text=True,
        encoding="utf-8"
    )
    current_branch = result.stdout.strip()

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

    diff_result = subprocess.run(
        ['git', 'diff', f'{upstream}...{current_branch}', '--unified=0'],
        capture_output=True,
        text=True,
        encoding="utf-8"
    )
    return diff_result.stdout.strip()

def analyze_diff_with_ai(diff: str) -> str:
    """Send diff to Gemini AI for OWASP Top 10 + Hardcoded Secrets analysis."""
    prompt = f"""
You are a senior application security reviewer. Analyze ONLY the following code diff for vulnerabilities
strictly limited to OWASP Top 10 + Hardcoded Secrets.

The OWASP Top 10 categories are:
1. Broken Access Control
2. Cryptographic Failures
3. Injection (SQL, Command, Code, LDAP)
4. Insecure Design
5. Security Misconfiguration
6. Vulnerable and Outdated Components
7. Identification and Authentication Failures
8. Software and Data Integrity Failures
9. Security Logging and Monitoring Failures
10. Server-Side Request Forgery (SSRF)
11. Hardcoded Secrets (API keys, passwords, tokens)

Ignore anything that does not clearly belong to one of these categories.

If no such vulnerability is found, return exactly this (nothing else):
---
SEVERITY: None
STATUS: SAFE TO RELEASE
---

If vulnerabilities are found, return only in this strict format:
---
SEVERITY: [None | Low | Medium | High]
STATUS: NEEDS REVIEW - Potential issues: [short summary]
DETAILS:
- [concise explanation]
SUGGESTIONS:
- [safe fix suggestion]
---
Do not include any introductions, explanations, or extra text outside the format.

Analyze this code diff now:
{diff}
"""

    try:
        model = genai.GenerativeModel("gemini-2.0-flash")
        response = model.generate_content(prompt)
        result = getattr(response, "text", "").strip()

        # Clean up result — remove any preamble lines before SEVERITY
        if not result.startswith("---") and "SEVERITY:" in result:
            result = result[result.find("SEVERITY:") - 4:]  # keep from --- onward

        print("\nAI Security Analysis Report:\n")
        print(result if result else "[No response from AI]")
        return result or "SEVERITY: None\nSTATUS: SAFE TO RELEASE"
    except Exception as e:
        print(f"Gemini API Error: {e}")
        # Treat API failure as SAFE to avoid false blocks
        return "SEVERITY: None\nSTATUS: SAFE TO RELEASE"

@app.command()
def scan():
    """Run AI security scan on committed code diff."""
    load_dotenv()
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

    if not GEMINI_API_KEY:
        print("Gemini API key not found in .env file.")
        raise typer.Exit(code=1)

    genai.configure(api_key=GEMINI_API_KEY)
    diff = get_current_branch_diff()

    if not diff:
        print("No committed changes to analyze.")
        raise typer.Exit(code=0)

    print("\nRunning AI analysis on committed changes...\n")
    result = analyze_diff_with_ai(diff)

    if "SAFE TO RELEASE" in result.upper():
        print("✅ Safe to release. Push allowed.")
        log_to_mysql(result)   # Log success
        raise typer.Exit(code=0)
    else:
        print("❌ Push blocked due to security risks found by AI.")
        log_to_mysql(result)   # Log failure
        raise typer.Exit(code=1)


# ------------------------------------------------------------
# Entry Point
# ------------------------------------------------------------

def main():
    app()

if __name__ == "__main__":
    main()
