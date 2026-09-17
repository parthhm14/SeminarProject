"""
Rule-Based SAST Engine for C/C++ Code Security Analysis.
Provides pattern matching rules inspired by static application security testing tools (e.g., Semgrep).
"""

import re
from typing import Dict, List, Any

class SASTRuleEngine:
    """
    Simulated SAST Rule Engine for C/C++ source code vulnerability scanning.
    """
    def __init__(self):
        self.rules = [
            {
                "id": "SAST-CWE-120-UNBOUNDED-STRCPY",
                "cwe": "CWE-120",
                "name": "Buffer Copy Without Checking Size (strcpy)",
                "severity": "HIGH",
                "pattern": r'\bstrcpy\s*\(\s*[^,]+,\s*[^)]+\)'
            },
            {
                "id": "SAST-CWE-120-UNBOUNDED-GETS",
                "cwe": "CWE-120",
                "name": "Use of Dangerous Function gets()",
                "severity": "CRITICAL",
                "pattern": r'\bgets\s*\(\s*[^)]+\)'
            },
            {
                "id": "SAST-CWE-134-FORMAT-STRING",
                "cwe": "CWE-134",
                "name": "Uncontrolled Format String in printf/sprintf",
                "severity": "HIGH",
                "pattern": r'\b(printf|sprintf)\s*\(\s*[A-Za-z_][A-Za-z0-9_]*\s*\)'
            },
            {
                "id": "SAST-CWE-78-COMMAND-INJECTION",
                "cwe": "CWE-78",
                "name": "Potential OS Command Injection (system call with dynamic string)",
                "severity": "CRITICAL",
                "pattern": r'\bsystem\s*\(\s*(?!"[^\"]*"\s*\))[^\)]+\)'
            },
            {
                "id": "SAST-CWE-415-DOUBLE-FREE",
                "cwe": "CWE-415",
                "name": "Potential Double Free Violation",
                "severity": "HIGH",
                "pattern": r'free\s*\(\s*(\w+)\s*\)\s*;(?:(?!\1\s*=\s*NULL|nullptr|0).)*\bfree\s*\(\s*\1\s*\)'
            },
            {
                "id": "SAST-CWE-416-USE-AFTER-FREE",
                "cwe": "CWE-416",
                "name": "Use-After-Free Pointer Access",
                "severity": "CRITICAL",
                "pattern": r'free\s*\(\s*(\w+)\s*\)\s*;(?:(?!\1\s*=\s*NULL|nullptr|0).)*\b(?:\*\1|\1->|\1\[)'
            },
            {
                "id": "SAST-CWE-476-UNCHECKED-MALLOC",
                "cwe": "CWE-476",
                "name": "Unchecked Return Value of Memory Allocation",
                "severity": "MEDIUM",
                "pattern": r'(\w+)\s*=\s*(?:\([^)]+\)\s*)?(?:malloc|calloc|realloc)\s*\([^)]+\)\s*;\s*(?!if\s*\(\s*!\s*\1|if\s*\(\s*\1\s*==\s*NULL|\1\s*!=\s*NULL)'
            },
            {
                "id": "SAST-CWE-190-INTEGER-OVERFLOW-ALLOC",
                "cwe": "CWE-190",
                "name": "Integer Overflow in Allocation Size Calculation",
                "severity": "HIGH",
                "pattern": r'(?:malloc|calloc|realloc)\s*\(\s*\w+\s*\*[\s\w\*]+\)'
            }
        ]

    def scan_code(self, code: str) -> Dict[str, Any]:
        """
        Scans a given C/C++ code string against all SAST rules.
        Returns scan details including flag count, detected findings, and status.
        """
        if not code or not isinstance(code, str):
            return {"status": "SAFE", "findings": [], "finding_count": 0, "is_suspicious": False}

        findings = []
        for rule in self.rules:
            matches = re.finditer(rule["pattern"], code, re.DOTALL | re.MULTILINE)
            for m in matches:
                findings.append({
                    "rule_id": rule["id"],
                    "cwe": rule["cwe"],
                    "name": rule["name"],
                    "severity": rule["severity"],
                    "matched_text": m.group(0)[:80]
                })

        finding_count = len(findings)
        is_suspicious = finding_count > 0
        status = "SUSPICIOUS" if is_suspicious else "SAFE"

        return {
            "status": status,
            "findings": findings,
            "finding_count": finding_count,
            "is_suspicious": is_suspicious
        }
