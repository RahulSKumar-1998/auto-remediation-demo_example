import os
import requests
from typing import Optional, Dict, Any

class ServiceNowClient:
    def __init__(self, instance_url: Optional[str] = None, user: Optional[str] = None, password: Optional[str] = None, use_env: bool = True):
        self.instance_url = instance_url
        self.user = user
        self.password = password
        
        if use_env:
             self.instance_url = self.instance_url or os.environ.get("SNOW_INSTANCE")
             self.user = self.user or os.environ.get("SNOW_USER")
             self.password = self.password or os.environ.get("SNOW_PASS")
        self.valid = bool(self.instance_url and self.user and self.password)

    def get_incident(self, incident_number: str) -> Optional[Dict[str, Any]]:
        """Retrieves incident details."""
        if not self.valid:
            print(f"[DEMO] Would fetch incident '{incident_number}' from ServiceNow.")
            return {"short_description": "Mock Incident: SQL Injection found", "state": "New"}

        url = f"{self.instance_url}/api/now/table/incident?sysparm_query=number={incident_number}"
        headers = {"Accept": "application/json"}
        resp = requests.get(url, auth=(self.user, self.password), headers=headers)
        
        if resp.status_code == 200:
            results = resp.json().get('result', [])
            if results:
                return results[0]
        return None

    def post_comment(self, incident_number: str, comment: str) -> bool:
        """Posts a work note/comment to the incident."""
        if not self.valid:
            print(f"[DEMO] Would post comment to '{incident_number}': {comment}")
            return True

        # Need sys_id to update. Theoretically we'd get it first.
        # For this simplified client, we assume getting sys_id via get_incident logic is implicit 
        # or we query by number to find it.
        
        # 1. Get Sys ID
        inc_data = self.get_incident(incident_number)
        if not inc_data or 'sys_id' not in inc_data:
            print(f"[-] Could not find incident {incident_number} to update.")
            return False
            
        sys_id = inc_data['sys_id']
        
        # 2. Update
        url = f"{self.instance_url}/api/now/table/incident/{sys_id}"
        payload = {"work_notes": comment}
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        
        resp = requests.put(url, auth=(self.user, self.password), headers=headers, json=payload)
        if resp.status_code == 200:
            print(f"[+] Comment added to {incident_number}")
            return True
        else:
            print(f"[-] Failed to update incident: {resp.text}")
            return False
    def create_incident(self, short_description: str, description: str, severity: str = "3") -> Optional[str]:
        """Creates a new incident and returns the incident number."""
        if not self.valid:
            print(f"[DEMO] Would create incident: {short_description}")
            return "INC_MOCK_001"

        url = f"{self.instance_url}/api/now/table/incident"
        payload = {
            "short_description": short_description,
            "description": description,
            "urgency": severity, # 1=High, 2=Medium, 3=Low
            "category": "security",
            "caller_id": self.user
        }
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        
        try:
            resp = requests.post(url, auth=(self.user, self.password), headers=headers, json=payload)
            if resp.status_code == 201:
                result = resp.json().get('result', {})
                number = result.get('number')
                print(f"[+] Incident created: {number}")
                return number
            else:
                print(f"[-] Failed to create incident: {resp.status_code} {resp.text}")
                return None
        except Exception as e:
            print(f"[-] Error creating incident: {e}")
            return None

    def download_attachment(self, incident_number: str, save_path: str = "downloaded_scan.json") -> Optional[str]:
        """Downloads the first JSON attachment from an incident. Returns local file path or None."""
        if not self.valid:
            print(f"[DEMO] Would download attachment from '{incident_number}'")
            return None

        # 1. Get incident sys_id
        inc_data = self.get_incident(incident_number)
        if not inc_data or 'sys_id' not in inc_data:
            print(f"[-] Could not find incident {incident_number} to download attachment.")
            return None

        sys_id = inc_data['sys_id']

        # 2. Query attachments for this incident
        url = f"{self.instance_url}/api/now/attachment?sysparm_query=table_name=incident^table_sys_id={sys_id}"
        headers = {"Accept": "application/json"}

        try:
            resp = requests.get(url, auth=(self.user, self.password), headers=headers)
            if resp.status_code != 200:
                print(f"[-] Failed to list attachments: {resp.status_code}")
                return None

            attachments = resp.json().get('result', [])
            # Find the first JSON attachment
            json_attachment = next((a for a in attachments if a.get('file_name', '').endswith('.json')), None)

            if not json_attachment:
                print(f"[~] No JSON attachment found on {incident_number}.")
                return None

            # 3. Download the file content
            download_url = json_attachment.get('download_link')
            print(f"[*] Downloading attachment: {json_attachment['file_name']}...")
            dl_resp = requests.get(download_url, auth=(self.user, self.password))

            if dl_resp.status_code == 200:
                with open(save_path, 'wb') as f:
                    f.write(dl_resp.content)
                print(f"[+] Attachment saved to: {save_path}")
                return save_path
            else:
                print(f"[-] Failed to download attachment: {dl_resp.status_code}")
                return None
        except Exception as e:
            print(f"[-] Error downloading attachment: {e}")
            return None

    def attach_file(self, incident_number: str, file_path: str) -> bool:
        """Uploads a file to the ServiceNow incident."""
        if not self.valid:
            print(f"[DEMO] Would attach '{file_path}' to '{incident_number}'")
            return True

        # 1. Get Sys ID
        inc_data = self.get_incident(incident_number)
        if not inc_data or 'sys_id' not in inc_data:
            print(f"[-] Could not find incident {incident_number} to attach file.")
            return False
            
        sys_id = inc_data['sys_id']
        file_name = os.path.basename(file_path)
        
        # 2. Upload
        url = f"{self.instance_url}/api/now/attachment/file?table_name=incident&table_sys_id={sys_id}&file_name={file_name}"
        headers = {"Content-Type": "*/*", "Accept": "application/json"}
        
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            resp = requests.post(url, auth=(self.user, self.password), headers=headers, data=data)
            
            if resp.status_code == 201:
                print(f"[+] File '{file_name}' attached to {incident_number}")
                return True
            else:
                print(f"[-] Failed to attach file: {resp.status_code} {resp.text}")
                return False
        except Exception as e:
            print(f"[-] Error attaching file: {e}")
            return False
