import re

class SecretScanner:
    def __init__(self):
        # Industrial signature regex array for active pattern matching
        self.signatures = {
            "AWS API Key": r"AKIA[0-9A-Z]{16}",
            "Slack Webhook": r"https://hooks\.slack\.com/services/T[A-Z0-9_]{8}/B[A-Z0-9_]{8}/[A-Za-z0-9_]{24}",
            "Generic Secret/Password": r"(password|secret|passwd|api_key|token)\s*=\s*['\"][^'\"]+['\"]"
        }

    def scan_file(self, file_path):
        detected_leaks = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    # Test every compiled signature array element against the raw text string
                    for secret_type, regex_pattern in self.signatures.items():
                        match = re.search(regex_pattern, line, re.IGNORECASE)
                        if match:
                            detected_leaks.append({
                                "line": line_num,
                                "type": secret_type,
                                "snippet": line.strip()
                            })
            return detected_leaks
        except FileNotFoundError:
            print(f"[-] Evaluation Error: Targeted configuration system '{file_path}' cannot be located locally.")
            return []
