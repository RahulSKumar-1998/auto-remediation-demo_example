import json
import csv
import os
from typing import List, Dict, Any

class BlackDuckParser:
    def __init__(self):
        pass

    def parse_file(self, file_path: str) -> List[Dict[str, Any]]:
        """
        Parses a Black Duck scan file (JSON or CSV) and returns a list of vulnerabilities.
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        _, ext = os.path.splitext(file_path)
        
        if ext.lower() == '.json':
            return self._parse_json(file_path)
        elif ext.lower() == '.csv':
            return self._parse_csv(file_path)
        else:
            raise ValueError(f"Unsupported file format: {ext}")

    def _parse_json(self, file_path: str) -> List[Dict[str, Any]]:
        with open(file_path, 'r') as f:
            data = json.load(f)
            
        # Validate that it's a list (which our sample is)
        if isinstance(data, list):
            return data
        # Handle if it's a dict with a "results" key or similar (common in API responses)
        elif isinstance(data, dict):
            # Try specific known keys or return the dict itself if it looks like a single vuln
            return data.get('items', data.get('results', [data])) 
        else:
            raise ValueError("Invalid JSON structure: Expected a list or dictionary.")

    def _parse_csv(self, file_path: str) -> List[Dict[str, Any]]:
        vulnerabilities = []
        with open(file_path, 'r', newline='') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                vulnerabilities.append(row)
        return vulnerabilities

if __name__ == "__main__":
    # Test with the sample file
    parser = BlackDuckParser()
    try:
        vulns = parser.parse_file("sample_blackduck_scan.json")
        print(f"Successfully parsed {len(vulns)} vulnerabilities.")
        for v in vulns:
            print(f"- {v.get('vulnerabilityId')}: {v.get('vulnerabilityName')}")
    except Exception as e:
        print(f"Error: {e}")
