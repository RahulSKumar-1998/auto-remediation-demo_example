import argparse
import sys
import os
import time
from black_duck_parser import BlackDuckParser

from sarif_generator import SarifGenerator
from github_client import GitHubClient
from servicenow_client import ServiceNowClient

from dotenv import load_dotenv

def main():
    # Load environment variables from .env file
    load_dotenv()

    parser = argparse.ArgumentParser(description="AI Vulnerability Remediation Orchestrator")
    parser.add_argument("--input", "-i", type=str, default="sample_blackduck_scan.json", help="Path to Black Duck scan file (JSON)")
    parser.add_argument("--output", "-o", type=str, default="results.sarif", help="Path to output SARIF file")
def run_remediation(incident_number, input_file="sample_blackduck_scan.json", output_file="results.sarif", mode="real", demo_mode=False, repo_name="auto-remediation-demo_example", base_branch="main"):
    """
    Core orchestration logic, callable from CLI or Webhook.
    """
    print(f"[*] Starting Orchestrator in '{mode}' mode for incident {incident_number}...")

    # 1. Initialize Clients
    if demo_mode:
        print("[*] Demo mode enabled. API calls will be mocked.")
    
    # Prefer a PAT (`COPILOT_API_TOKEN`) over `GITHUB_TOKEN` to allow PR creation to recursively trigger Actions
    gh_token = os.environ.get("COPILOT_API_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if demo_mode:
        gh_token = None
        
    gh_client = GitHubClient(token=gh_token, use_env=not demo_mode)
    sn_client = ServiceNowClient(instance_url=None if demo_mode else os.environ.get("SNOW_INSTANCE"), use_env=not demo_mode)

    # Fetch incident details to include in PR titles
    inc_data = sn_client.get_incident(incident_number)
    incident_name = inc_data.get('short_description', 'Vulnerability Scan') if inc_data else 'Vulnerability Scan'

    # 2. Parse Vulnerabilities
    print(f"[*] Parsing input file: {input_file}")
    try:
        bd_parser = BlackDuckParser()
        vulnerabilities = bd_parser.parse_file(input_file)
        print(f"[+] Found {len(vulnerabilities)} vulnerabilities.")
    except Exception as e:
        print(f"[-] Error parsing file: {e}")
        return False

    # 3. Mode: Prepare (Just generate SARIF for manual upload)
    if mode == 'prepare':
        print("[*] Generating SARIF for manual upload...")
        sarif_gen = SarifGenerator()
        # In prepare mode, we don't have fixes yet, so pass empty list or placeholder
        sarif_data = sarif_gen.generate_sarif(vulnerabilities, ["Analysis pending..."] * len(vulnerabilities))
        sarif_gen.save_sarif(sarif_data, output_file)
        print(f"[+] SARIF saved to {output_file}")
        return True

    # 4. Mode: GHAS (Upload SARIF to trigger GitHub Copilot Autofix)
    if mode == 'ghas':
        # Step A: Ensure Repo Exists
        print(f"[*] Ensuring repository '{repo_name}' exists...")
        env_repo = os.environ.get("GITHUB_REPOSITORY")
        if env_repo:
            print(f"[*] Running in GitHub Actions. Using exact repo: {env_repo}")
            full_repo_name = env_repo
        else:
            repo_data = gh_client.create_repo(repo_name)
            full_repo_name = repo_data.get("full_name", f"demo-user/{repo_name}") if repo_data else f"demo-user/{repo_name}"
        
        # KEY FIX: Helper to ensure CodeQL works -> Push pom.xml to MAIN first
        print("[*] Pushing pom.xml to main (Required for CodeQL Java analysis)...")
        if os.path.exists("pom.xml"):
            with open("pom.xml", "r") as f:
                gh_client.push_file(full_repo_name, "pom.xml", f.read(), "Add Maven build configuration")
        
        # KEY FIX 2: Force CodeQL to scan Python by adding a Workflow file
        print("[*] Pushing CodeQL Workflow to main (Forces Python + Java scan)...")
        if os.path.exists("codeql-analysis.yml"):
            with open("codeql-analysis.yml", "r") as f:
                # We update the file content to ensure it picks up the "Manual Build" change
                gh_client.push_file(full_repo_name, ".github/workflows/codeql.yml", f.read(), "Fix CodeQL Build Configuration")
        
        # Step B: Create a Feature Branch & PR (Standard Developer Workflow)
        
        feature_branch = f"submit-new-vulns-{int(time.time())}"
        print(f"[*] Creating feature branch '{feature_branch}'...")
        gh_client.create_branch(full_repo_name, base_branch, feature_branch)
        
        print("[*] Pushing NEW vulnerable code artifacts to feature branch...")
        
        timestamp_comment_java = f"\n// Auto-generated update: {int(time.time())}"
        timestamp_comment_python = f"\n# Auto-generated update: {int(time.time())}"
        
        # 1. SQL Injection
        with open("src/main/java/com/example/vuln/SQLInjection.java", "r") as f:
            content = f.read() + timestamp_comment_java
            gh_client.push_file(full_repo_name, "src/main/java/com/example/vuln/SQLInjection.java", content, "Add SQL Injection sample", branch=feature_branch)

        # 2. XSS
        with open("src/main/java/com/example/vuln/XSS.java", "r") as f:
            content = f.read() + timestamp_comment_java
            gh_client.push_file(full_repo_name, "src/main/java/com/example/vuln/XSS.java", content, "Add XSS sample", branch=feature_branch)

        # 3. Weak Crypto (Python)
        with open("weak_crypto.py", "r") as f:
            content = f.read() + timestamp_comment_python
            gh_client.push_file(full_repo_name, "weak_crypto.py", content, "Add weak crypto sample", branch=feature_branch)

        # 3. FIX BUILD: Push Database.java and UserAuth.java (with import) to ensure compilation
        # Even though these are old samples, they might exist in the repo and break the build if incomplete.
        print("[*] Ensuring build dependencies (Database.java) are present...")
        with open("src/main/java/com/example/util/Database.java", "r") as f:
             gh_client.push_file(full_repo_name, "src/main/java/com/example/util/Database.java", f.read(), "Ensure Database helper exists", branch=feature_branch)

        with open("src/main/java/com/example/auth/UserAuth.java", "r") as f:
             # Inject the missing import if needed
             original_content = f.read()
             if "import com.example.util.Database;" not in original_content:
                 fixed_content = "package com.example.auth;\nimport com.example.util.Database;\n" + original_content.replace("package com.example.auth;", "")
             else:
                 fixed_content = original_content
             gh_client.push_file(full_repo_name, "src/main/java/com/example/auth/UserAuth.java", fixed_content, "Fix UserAuth compilation (add import)", branch=feature_branch)

        print("[*] creating Pull Request for vulnerable code...")
        pr_title = f"{incident_name} [{incident_number}]"
        pr_url = gh_client.create_pr(full_repo_name, pr_title, "Adding new file handling module and config.", feature_branch, base_branch)
        
        if pr_url:
            print(f"[+] Pull Request created: {pr_url}")
            # Update ServiceNow to track this PR
            try:
                sn_client.post_comment(incident_number, f"Vulnerable code submitted. Scanning via PR: {pr_url}")
            except Exception as e:
                print(f"[-] Warning: Failed to update ServiceNow (Check .env credentials): {e}")

        # Step C: Generate & Upload SARIF for this Branch
        print("[*] Generating SARIF for GitHub Upload...")
        sarif_gen = SarifGenerator()
        sarif_data = sarif_gen.generate_sarif(vulnerabilities, []) 
        sarif_gen.save_sarif(sarif_data, output_file)
        
        print(f"[*] Uploading SARIF to {full_repo_name} (ref: {feature_branch}) to trigger Copilot Autofix...")
        # CRITICAL: We upload to the FEATURE BRANCH so checks appear on the PR
        gh_client.upload_sarif(full_repo_name, output_file, feature_branch)
        
        print(f"[+] Upload complete. Visit the PR URL above. You should see 'Code scanning results' and Copilot suggestions appear there shortly.")
        return True

    # 5. Mode: Real/Simulate (Full Loop)
    
    # Step A: Ensure Repo Exists & Has Code (For Demo purposes)
    print(f"[*] Ensuring repository '{repo_name}' exists...")
    env_repo = os.environ.get("GITHUB_REPOSITORY")
    if env_repo:
        print(f"[*] Running in GitHub Actions. Using exact repo: {env_repo}")
        full_repo_name = env_repo
    else:
        repo_data = gh_client.create_repo(repo_name)
        full_repo_name = repo_data.get("full_name", f"demo-user/{repo_name}") if repo_data else f"demo-user/{repo_name}"

    # KEY FIX: Helper to ensure CodeQL works -> Push pom.xml to MAIN first
    print("[*] Pushing pom.xml to main (Required for CodeQL Java analysis)...")
    if os.path.exists("pom.xml"):
        with open("pom.xml", "r") as f:
            gh_client.push_file(full_repo_name, "pom.xml", f.read(), "Add Maven build configuration")
    
    # KEY FIX 2: Force CodeQL to scan Python by adding a Workflow file
    print("[*] Pushing CodeQL Workflow to main (Forces Python + Java scan)...")
    if os.path.exists("codeql-analysis.yml"):
        with open("codeql-analysis.yml", "r") as f:
            # We update the file content to ensure it picks up the "Manual Build" change
            gh_client.push_file(full_repo_name, ".github/workflows/codeql.yml", f.read(), "Fix CodeQL Build Configuration")
            
    # KEY FIX 3: Push the Auto Remediation Worker workflow
    print("[*] Pushing Auto-Remediate Workflow to main...")
    if os.path.exists(".github/workflows/auto_remediate.yml"):
        with open(".github/workflows/auto_remediate.yml", "r") as f:
            gh_client.push_file(full_repo_name, ".github/workflows/auto_remediate.yml", f.read(), "Add Auto Remediation Workflow")
            
    # KEY FIX 4: Push the Orchestrator Webhook Workflow
    print("[*] Pushing Webhook Orchestrator Workflow to main...")
    if os.path.exists(".github/workflows/remediation_orchestrator.yml"):
        with open(".github/workflows/remediation_orchestrator.yml", "r") as f:
            gh_client.push_file(full_repo_name, ".github/workflows/remediation_orchestrator.yml", f.read(), "Add ORCHESTRATOR Webhook Workflow")
            
    # KEY FIX 5: Push the updated worker script so the workflow doesn't crash on old args
    print("[*] Pushing updated remediation worker to main...")
    if os.path.exists("remediation_worker.py"):
        with open("remediation_worker.py", "r", encoding="utf-8") as f:
            gh_client.push_file(full_repo_name, "remediation_worker.py", f.read(), "Update Remediation Worker Script")

    # KEY FIX 6: Push ALL orchestration scripts so the Webhook Action can run main.py in the cloud
    print("[*] Pushing Core Orchestration dependencies to main...")
    core_files = [
        "main.py", 
        "github_client.py", 
        "servicenow_client.py", 
        "sarif_generator.py", 
        "black_duck_parser.py",
        "sample_blackduck_scan.json"
    ]
    for file_name in core_files:
        if os.path.exists(file_name):
            with open(file_name, "r", encoding="utf-8") as f:
                gh_client.push_file(full_repo_name, file_name, f.read(), f"Update Orchestrator dependency: {file_name}")
    
    
    # Push vulnerable code (Simulating the state of the repo)
    print("\n[*] Pushing vulnerable code artifacts...")
    
    # Database Helper for UserAuth/SQLi
    with open("src/main/java/com/example/util/Database.java", "r") as f:
        gh_client.push_file(full_repo_name, "src/main/java/com/example/util/Database.java", f.read(), "Add database helper")

    # New Vulnerability Files
    with open("src/main/java/com/example/vuln/SQLInjection.java", "r") as f:
        gh_client.push_file(full_repo_name, "src/main/java/com/example/vuln/SQLInjection.java", f.read(), "Add SQL Injection sample")

    with open("src/main/java/com/example/vuln/XSS.java", "r") as f:
        gh_client.push_file(full_repo_name, "src/main/java/com/example/vuln/XSS.java", f.read(), "Add XSS sample")
    
    with open("weak_crypto.py", "r") as f:
        gh_client.push_file(full_repo_name, "weak_crypto.py", f.read(), "Add weak crypto sample")

    # Step C: Trigger GitHub Copilot Autofix (via PR)
    print("\n--- Triggering GitHub Advanced Security (Copilot Autofix) ---")
    
    # We create a specific branch just for triggering the SARIF upload and Autofix
    ghas_branch = f"submit-vulnerability-ghas-{int(time.time())}"
    print(f"[*] Creating branch '{ghas_branch}' for GHAS trigger...")
    gh_client.create_branch(full_repo_name, base_branch, ghas_branch)

    # KEY FIX: Must push a commit to this branch so it differs from Main, otherwise PR creation fails
    print("[*] Pushing trigger commit to GHAS branch...")
    with open("unsafe.py", "r") as f:
        # Append a newline/comment to force a SHA change
        trigger_content = f.read() + f"\n# GHAS Trigger: {int(time.time())}"
        gh_client.push_file(full_repo_name, "unsafe.py", trigger_content, "Trigger GHAS Scan", branch=ghas_branch)
    
    # Create a PR for this branch so Autofix has somewhere to post
    print("[*] Creating PR for GHAS Analysis...")
    pr_title = f"{incident_name} [{incident_number}]"
    ghas_pr_url = gh_client.create_pr(full_repo_name, pr_title, "Triggering CodeQL and Copilot Autofix", ghas_branch, base_branch)
    print(f"[+] GHAS PR Created: {ghas_pr_url}")

    print("[*] Generating SARIF for GitHub Upload...")
    sarif_gen = SarifGenerator()
    sarif_data = sarif_gen.generate_sarif(vulnerabilities, []) 
    sarif_gen.save_sarif(sarif_data, output_file)
    
    print(f"[*] Uploading SARIF to {full_repo_name} (ref: {ghas_branch})...")
    gh_client.upload_sarif(full_repo_name, output_file, ghas_branch)
    
    print(f"[+] Full Orchestration complete!")
    print(f"    1. Vertex AI Fixes: Check the 'fix/...' PRs")
    print(f"    2. Copilot Autofix: Check the '{ghas_branch}' PR")
    return True

def main():
    # Load environment variables from .env file
    load_dotenv()

    parser = argparse.ArgumentParser(description="AI Vulnerability Remediation Orchestrator")
    parser.add_argument("--input", "-i", type=str, default="sample_blackduck_scan.json", help="Path to Black Duck scan file (JSON)")
    parser.add_argument("--output", "-o", type=str, default="results.sarif", help="Path to output SARIF file")
    parser.add_argument("--mode", type=str, choices=['simulate', 'prepare', 'real', 'ghas'], default='simulate', help="Execution mode")
    parser.add_argument("--demo", action="store_true", help="Run in demo mode (mocks API calls)")
    parser.add_argument("--incident", type=str, default="INC0012345", help="ServiceNow Incident Number")
    
    args = parser.parse_args()

    # Configuration
    REPO_NAME = "auto-remediation-demo_example"
    BASE_BRANCH = "main"

    run_remediation(
        incident_number=args.incident,
        input_file=args.input,
        output_file=args.output,
        mode=args.mode,
        demo_mode=args.demo,
        repo_name=REPO_NAME,
        base_branch=BASE_BRANCH
    )

if __name__ == "__main__":
    main()
