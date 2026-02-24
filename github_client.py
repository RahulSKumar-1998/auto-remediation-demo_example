import os
import requests
import base64
from typing import Optional

class GitHubClient:
    def __init__(self, token: Optional[str] = None, use_env: bool = True):
        self.token = token
        if not self.token and use_env:
            self.token = os.environ.get("GITHUB_TOKEN")
        self.api_url = "https://api.github.com"
        self.headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github.v3+json"
        }
        self.user_login = self._get_user_login() if self.token else None

    def _get_user_login(self) -> str:
        """Fetch the authenticated user's login."""
        if not self.token: return "unknown"
        resp = requests.get(f"{self.api_url}/user", headers=self.headers)
        if resp.status_code == 200:
            return resp.json()["login"]
        return "unknown"

    def create_repo(self, name: str, description: str = "Auto-created by Remediation Bot", auto_init: bool = True) -> Optional[dict]:
        """Creates a new repository."""
        if not self.token:
            print(f"[DEMO] Would create repo '{name}'")
            return {"full_name": f"demo-user/{name}", "html_url": f"https://github.com/demo-user/{name}"}

        url = f"{self.api_url}/user/repos"
        payload = {
            "name": name,
            "description": description,
            "private": True,
            "auto_init": auto_init
        }
        resp = requests.post(url, headers=self.headers, json=payload)
        if resp.status_code == 201:
            print(f"[+] Repository created: {resp.json().get('html_url')}")
            return resp.json()
        elif resp.status_code == 422: # Already exists
            print(f"[*] Repository '{name}' likely already exists.")
            return self.get_repo(self.user_login, name)
        else:
            print(f"[-] Failed to create repo: {resp.status_code} {resp.text}")
            return None

    def get_repo(self, owner: str, name: str) -> Optional[dict]:
        url = f"{self.api_url}/repos/{owner}/{name}"
        resp = requests.get(url, headers=self.headers)
        if resp.status_code == 200:
            return resp.json()
        return None

    def create_branch(self, repo_full_name: str, base_branch: str, new_branch: str) -> bool:
        """Creates a new branch from the base branch."""
        if not self.token:
            print(f"[DEMO] Would create branch '{new_branch}' on '{repo_full_name}'")
            return True

        # 1. Get SHA of base branch
        url_ref = f"{self.api_url}/repos/{repo_full_name}/git/ref/heads/{base_branch}"
        resp = requests.get(url_ref, headers=self.headers)
        if resp.status_code != 200:
            print(f"[-] Base branch '{base_branch}' not found.")
            return False
        
        sha = resp.json()["object"]["sha"]

        # 2. Create new ref
        url_create = f"{self.api_url}/repos/{repo_full_name}/git/refs"
        payload = {
            "ref": f"refs/heads/{new_branch}",
            "sha": sha
        }
        resp = requests.post(url_create, headers=self.headers, json=payload)
        if resp.status_code == 201:
            print(f"[+] Branch '{new_branch}' created.")
            return True
        elif resp.status_code == 422:
             print(f"[*] Branch '{new_branch}' already exists.")
             return True
        return False

    def push_file(self, repo_full_name: str, path: str, content: str, message: str, branch: str = "main") -> bool:
        """Creates or updates a file in the repository."""
        if not self.token:
            print(f"[DEMO] Would push file '{path}' to '{repo_full_name}' on branch '{branch}'")
            return True

        url = f"{self.api_url}/repos/{repo_full_name}/contents/{path}"
        
        # Check if file exists to get SHA (for update)
        resp_check = requests.get(url, headers=self.headers, params={"ref": branch})
        sha = ""
        if resp_check.status_code == 200:
            sha = resp_check.json()["sha"]

        payload = {
            "message": message,
            "content": base64.b64encode(content.encode()).decode(),
            "branch": branch
        }
        if sha:
            payload["sha"] = sha

        resp = requests.put(url, headers=self.headers, json=payload)
        if resp.status_code in [200, 201]:
            print(f"[+] File '{path}' pushed to branch '{branch}'.")
            return True
        else:
            print(f"[-] Parse error pushing file: {resp.text}")
            return False

    def create_pr(self, repo_full_name: str, title: str, body: str, head: str, base: str) -> Optional[str]:
        """Creates a Pull Request."""
        if not self.token:
            print(f"[DEMO] Would create PR '{title}' from '{head}' to '{base}'")
            return "https://github.com/demo-user/repo/pull/1"

        url = f"{self.api_url}/repos/{repo_full_name}/pulls"
        payload = {
            "title": title,
            "body": body,
            "head": head,
            "base": base
        }
        resp = requests.post(url, headers=self.headers, json=payload)
        if resp.status_code == 201:
            pr_url = resp.json().get('html_url')
            print(f"[+] Pull Request created: {pr_url}")
            return pr_url
        else:
            print(f"[-] Failed to create PR: {resp.text}")
            return None

    def upload_sarif(self, repo_full_name: str, sarif_path: str, ref: str) -> bool:
        """Uploads a SARIF file to GitHub Code Scanning."""
        if not self.token:
            print(f"[DEMO] Would upload SARIF '{sarif_path}' to '{repo_full_name}' for ref '{ref}'")
            return True

        if not os.path.exists(sarif_path):
            print(f"[-] SARIF file not found: {sarif_path}")
            return False

        # Compress SARIF (gzip) - GitHub requires/recommends it, but raw JSON often works. 
        # Standard API expects plain text or gzipped base64. 
        # For simplicity in this script, we'll try just reading it.
        # However, the endpoint is `POST /repos/{owner}/{repo}/code-scanning/sarifs`
        
        with open(sarif_path, "r") as f:
            sarif_content = f.read()
        
        # We need to gzip and base64 encode for the API
        import gzip
        import base64
        
        compressed = gzip.compress(sarif_content.encode('utf-8'))
        b64_sarif = base64.b64encode(compressed).decode('utf-8')

        url = f"{self.api_url}/repos/{repo_full_name}/code-scanning/sarifs"
        payload = {
            "commit_sha": self._get_latest_commit_sha(repo_full_name, ref), 
            "ref": f"refs/heads/{ref}",
            "sarif": b64_sarif,
            "tool_name": "Black Duck Import"
        }
        
        resp = requests.post(url, headers=self.headers, json=payload)
        if resp.status_code == 202:
            print(f"[+] SARIF uploaded successfully. GitHub will process it shortly.")
            return True
        else:
            print(f"[-] Failed to upload SARIF: {resp.status_code} {resp.text}")
            return False

    def _get_latest_commit_sha(self, repo_full_name: str, branch: str) -> str:
        """Helper to get the SHA of the branch tip."""
        if not self.token: return "mock_sha"
        url = f"{self.api_url}/repos/{repo_full_name}/git/ref/heads/{branch}"
        resp = requests.get(url, headers=self.headers)
        if resp.status_code == 200:
            return resp.json()["object"]["sha"]
        return ""
