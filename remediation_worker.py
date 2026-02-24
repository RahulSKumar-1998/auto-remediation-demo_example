import os
import json
import argparse
import subprocess
from dotenv import load_dotenv
from sarif_generator import SarifGenerator

load_dotenv()

from openai import OpenAI

def generate_fix_with_copilot(vuln_name, description, remediation, file_content):
    """Uses GitHub Models API to generate a remediation code snippet using Copilot (gpt-4o)."""
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        return "> **Error**: `GITHUB_TOKEN` environment variable is not set. Cannot use GitHub Models API."

    try:
        client = OpenAI(
            base_url="https://models.inference.ai.azure.com",
            api_key=token,
        )

        prompt = f"""
You are an expert security engineer. A vulnerability has been found in the following code.
Vulnerability: {vuln_name}
Description: {description}
Suggested Remediation: {remediation}

Original File Content:
```
{file_content}
```

Please provide a code snippet fixing this issue. Output the suggested fix in Markdown (e.g., using ```python or ```java blocks). Focus only on the modified part of the file, not the entire file, but provide enough context to show where the change belongs.
"""

        response = client.chat.completions.create(
            messages=[
                {
                    "role": "system",
                    "content": "You are an expert security engineer assistant that fixes vulnerabilities.",
                },
                {
                    "role": "user",
                    "content": prompt,
                }
            ],
            model="gpt-4o",
            temperature=0.2,
            max_tokens=1000,
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"> **Error generating fix with Copilot**: {str(e)}"

import requests

def post_github_comment(pr_url_or_number: str, body: str):
    """Posts a comment to the PR, falling back to REST API if gh CLI is missing."""
    print(f"[*] Attempting to post comment...")
    
    # Try GH CLI first
    try:
        subprocess.run(["gh", "pr", "comment", pr_url_or_number, "--body", body], check=True, capture_output=True)
        print(f"[+] Posted comment via GH CLI")
        return
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass

    # Fallback to REST API
    token = os.environ.get("GITHUB_TOKEN")
    if not token or not "github.com" in pr_url_or_number.lower():
        safe_body = body.encode('ascii', errors='replace').decode('ascii')
        print(f"[-] Dropping comment for dry-run viewing:\n{safe_body}\n---")
        return

    try:
        # Extract repo and PR number from URL: https://github.com/owner/repo/pull/12
        parts = pr_url_or_number.split('/')
        repo_owner_name = f"{parts[-4]}/{parts[-3]}"
        pr_number = parts[-1]
        
        api_url = f"https://api.github.com/repos/{repo_owner_name}/issues/{pr_number}/comments"
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github.v3+json"
        }
        res = requests.post(api_url, headers=headers, json={"body": body})
        if res.status_code == 201:
            print(f"[+] Posted comment via REST API to PR #{pr_number}")
        else:
            print(f"[-] Failed to post via REST API: {res.status_code} - {res.text}")
    except Exception as e:
        print(f"[-] Failed to post comment entirely: {e}")

def main():
    parser = argparse.ArgumentParser(description="Remediation Worker for CI")
    parser.add_argument("--mode", type=str, default="sarif", choices=["sarif", "fixes"], help="Operation mode")
    parser.add_argument("--payload", type=str, help="JSON payload from ServiceNow/GitHub Dispatch")
    parser.add_argument("--scan-file", type=str, default="sample_blackduck_scan.json", help="Path to local scan file")
    parser.add_argument("--output", type=str, default="results.sarif", help="Output SARIF file")
    parser.add_argument("--pr-url", type=str, help="Pull Request URL or Number for commenting")
    
    args = parser.parse_args()
    
    vulnerabilities = []
    
    # Load Vulnerabilities (Common step)
    if args.payload:
        try:
            data = json.loads(args.payload)
            if 'vulnerabilities' in data:
                vulnerabilities = data['vulnerabilities']
        except json.JSONDecodeError:
            pass

    if not vulnerabilities and os.path.exists(args.scan_file):
        with open(args.scan_file, 'r') as f:
            vulnerabilities = json.load(f)

    # MODE: SARIF GENERATION
    if args.mode == "sarif":
        print("[*] Generating SARIF...")
        sarif_gen = SarifGenerator()
        sarif_data = sarif_gen.generate_sarif(vulnerabilities, ["Analysis pending" for _ in vulnerabilities])
        sarif_gen.save_sarif(sarif_data, args.output)
        print(f"[+] SARIF saved to {args.output}")

    # MODE: APPLY FIXES (COMMENTS)
    elif args.mode == "fixes":
        print("[*] Applying Fixes via Comments...")
        if not args.pr_url:
            print("[-] PR URL/Number required for fixes mode.")
            return

        for vuln in vulnerabilities:
            vuln_name = vuln.get('vulnerabilityName', 'Unknown Vulnerability')
            desc = vuln.get('description', '')
            remedy = vuln.get('remediation', '')
            file_path = vuln.get('location')

            if file_path and os.path.exists(file_path):
                print(f"[*] Reading file {file_path} for context...")
                with open(file_path, "r", encoding="utf-8") as f:
                    file_content = f.read()

                print(f"[*] Generating fix for {vuln_name} using Copilot...")
                snippet = generate_fix_with_copilot(vuln_name, desc, remedy, file_content)

                comment_body = f"### 🛡️ Automated Remediation Suggestion\n**Vulnerability**: {vuln_name}\n\n{snippet}\n\n*Apply this change to `{file_path}`.*"
                post_github_comment(args.pr_url, comment_body)
            else:
                print(f"[-] Could not read file {file_path} for vulnerability {vuln_name}. Skipping fix generation.")

if __name__ == "__main__":
    main()
