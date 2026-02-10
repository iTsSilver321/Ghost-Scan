import re
from typing import Dict, Any, List
from .signatures import SIGNATURES

class Fingerprinter:
    def __init__(self):
        self.signatures = SIGNATURES

    def analyze(self, banner: str, port: int = 0) -> Dict[str, str]:
        """
        Analyze a banner string and return a dictionary with fingerprint data.
        """
        result = {
            "product": "Unknown",
            "version": "Unknown",
            "os": "Unknown",
            "device_type": "Unknown"
        }
        
        # 1. Port-based Heuristics (if banner is weak)
        if port == 445 or port == 139:
            result["os"] = "Windows (Likely)"
        elif port == 22:
            result["os"] = "Linux/Unix"
        elif port == 3389:
            result["os"] = "Windows"
            result["product"] = "RDP"
        elif port == 62078: # common lockdown port
            result["os"] = "iOS"
            result["device_type"] = "Mobile"
        
        if not banner or banner == "Unknown":
            return result

        # 2. Signature-based (Overwrites port heuristic if specific match found)
        for pattern, name, category, extra in self.signatures:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                if category == "ver":
                    result["product"] = name
                    result["version"] = match.group(1)
                    if extra:
                        result["os"] = extra # Initial guess, can be overwritten
                elif category == "os":
                    result["os"] = name
                elif category == "app":
                    result["product"] = name
                    result["device_type"] = extra
                    if result["os"] == "Unknown":
                         result["os"] = extra

        return result
