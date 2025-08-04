import typer
import os
import subprocess
import sys
from dotenv import load_dotenv
import google.generativeai as genai

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
def scan():
    """Run AI security scan on committed code diff."""
    load_dotenv()
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

    if not GEMINI_API_KEY:
        print("❌ Gemini API key not found in .env file.")
        raise typer.Exit(code=1)

    genai.configure(api_key=GEMINI_API_KEY)

    diff = get_current_branch_diff()

    if not diff:
        print("✅ No committed changes to analyze.")
        raise typer.Exit(code=0)

    print("\n🔍 Running AI analysis on committed changes...\n")
    result = analyze_diff_with_ai(diff)

    if "SAFE TO RELEASE" in result.upper():
        print("Safe to release. Push allowed.")
        raise typer.Exit(code=0)
    else:
        print("Push blocked due to security risks found by AI.")
        raise typer.Exit(code=1)


def get_current_branch_diff():
    # Get current branch
    result = subprocess.run(
    ['git', 'rev-parse', '--abbrev-ref', 'HEAD'],
    capture_output=True,
    text=True,
    encoding="utf-8"  # ✅ ADD THIS
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
You are a senior security code reviewer. A developer is trying to push the following committed code changes:

{diff}

Your job is to:
1. Identify security vulnerabilities (especially OWASP Top 10)
2. Focus on:
- Code injection (eval, exec)
- Command injection (os.system, subprocess)
- SQL injection (raw queries, string formatting)
- Hardcoded credentials or API keys
- Insecure deserialization
- Dangerous file handling or permissions
- XSS (for web)
3. Provide a severity rating (Low, Medium, High)
4. Output a structured result like:

---
SEVERITY: High  
STATUS: NEEDS REVIEW - Potential issues: [summary]  
DETAILS:
- [explanation]
- [file/line if possible]
SUGGESTIONS:
- [fix or better practice]
---

If no issues found, reply with:
---
SEVERITY: None  
STATUS: SAFE TO RELEASE  
---
"""

    model = genai.GenerativeModel("gemini-1.5-flash")

    try:
        response = model.generate_content(prompt)
        result = getattr(response, "text", "").strip()

        print("\n📄 AI Security Analysis Report:\n")
        print(result)
        return result
    except Exception as e:
        print("Gemini API Error:", e)
        return "NEEDS REVIEW - AI check failed"

def main():
    app()

if __name__ == "__main__":
    main()
