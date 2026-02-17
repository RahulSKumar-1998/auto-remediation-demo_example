import os
import json
import argparse
from sarif_generator import SarifGenerator

def main():
    parser = argparse.ArgumentParser(description="Remediation Worker for CI")
    parser.add_argument("--payload", type=str, help="JSON payload from ServiceNow/GitHub Dispatch")
    parser.add_argument("--scan-file", type=str, default="sample_blackduck_scan.json", help="Path to local scan file if payload missing")
    parser.add_argument("--output", type=str, default="results.sarif", help="Output SARIF file")
    
    args = parser.parse_args()
    
    vulnerabilities = []
    
    # 1. Try to get vulnerabilities from Payload argument
    if args.payload:
        try:
            data = json.loads(args.payload)
            if 'vulnerabilities' in data:
                vulnerabilities = data['vulnerabilities']
                print(f"[*] Loaded {len(vulnerabilities)} vulnerabilities from payload.")
        except json.JSONDecodeError:
            print("[-] Error decoding payload JSON.")

    # 2. Fallback: Load from file (simulating fetching from artifacts/servicenow)
    if not vulnerabilities:
        if os.path.exists(args.scan_file):
            print(f"[*] Loading vulnerabilities from local file: {args.scan_file}")
            with open(args.scan_file, 'r') as f:
                vulnerabilities = json.load(f)
        else:
            print("[-] No vulnerability data found.")
            return

    # 3. Generate SARIF
    print("[*] Generating SARIF...")
    sarif_gen = SarifGenerator()
    sarif_data = sarif_gen.generate_sarif(vulnerabilities, ["Analysis pending (GHAS)" for _ in vulnerabilities])
    
    # 4. Save
    sarif_gen.save_sarif(sarif_data, args.output)
    print(f"[+] SARIF saved to {args.output}")

if __name__ == "__main__":
    main()
