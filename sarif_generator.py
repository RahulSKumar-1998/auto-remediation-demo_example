import json
from typing import List, Dict, Any

class SarifGenerator:
    def __init__(self):
        self.version = "2.1.0"
        self.schema = "https://json.schemastore.org/sarif-2.1.0.json"

    def generate_sarif(self, vulnerabilities: List[Dict[str, Any]], remediations: List[str]) -> Dict[str, Any]:
        """
        Converts vulnerabilities and their remediations into a SARIF report object.
        """
        results = []
        
        for i, vuln in enumerate(vulnerabilities):
            remediation_text = remediations[i] if i < len(remediations) else "No remediation available."
            
            result = {
                "ruleId": vuln.get('vulnerabilityId', 'UNKNOWN_RULE'),
                "level": self._map_severity(vuln.get('severity', 'MEDIUM')),
                "message": {
                    "text": vuln.get('description', 'No description provided.')
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": vuln.get('location', 'unknown/file')
                            },
                            "region": {
                                "startLine": int(vuln.get('line', 1))
                            }
                        }
                    }
                ],
                "codeFlows": [
                     {
                        "threadFlows": [
                            {
                                "locations": [
                                    {
                                        "location": {
                                            "message": {
                                                "text": "Vulnerability detected here."
                                            },
                                            "physicalLocation": {
                                                "artifactLocation": {
                                                    "uri": vuln.get('location', 'unknown/file')
                                                },
                                                "region": {
                                                     "startLine": int(vuln.get('line', 1))
                                                }
                                            }
                                        }
                                    }
                                ]
                            }
                        ]
                     }
                ],
                # In SARIF, fixes are complex. We'll add the AI suggestion as a markdown property 
                # or a 'suggestedFix' attached to the result.
                # For simplicity in this demo, we append it to the message or use a property bag.
                "properties": {
                    "ai_remediation_suggestion": remediation_text
                }
            }
            results.append(result)

        sarif_output = {
            "version": self.version,
            "$schema": self.schema,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Black Duck + AI Remediation",
                            "informationUri": "https://www.blackduck.com/",
                            "rules": [] # In a full implementation, we'd list rules here
                        }
                    },
                    "results": results
                }
            ]
        }
        
        return sarif_output

    def _map_severity(self, severity: str) -> str:
        """Maps Black Duck severity to SARIF levels (error, warning, note)."""
        severity = severity.upper()
        if severity in ['CRITICAL', 'HIGH']:
            return 'error'
        elif severity == 'MEDIUM':
            return 'warning'
        else:
            return 'note'

    def save_sarif(self, sarif_data: Dict[str, Any], output_path: str):
        with open(output_path, 'w') as f:
            json.dump(sarif_data, f, indent=2)

if __name__ == "__main__":
    # Test generator
    gen = SarifGenerator()
    test_vuln = [{
        "vulnerabilityId": "Test",
        "description": "Test Desc",
        "location": "test.py",
        "line": 1,
        "severity": "HIGH"
    }]
    test_rem = ["Fix this by doing X."]
    sarif = gen.generate_sarif(test_vuln, test_rem)
    print(json.dumps(sarif, indent=2))
