import re
import json
import os

class SignatureParser:
    def __init__(self, rules_file="rules/protocol/http/emerging-all.rules"):
        self.rules_file = rules_file
        # We only care about high-value categories to keep the engine fast
        self.target_categories = ["EXPLOIT", "MALWARE", "TROJAN", "ATTACK_RESPONSE", "CNC"]

    def parse_and_export(self):
        """Parses raw Suricata rules and exports them to our optimized JSON format."""
        print(f"[SigParser] Starting conversion of {self.rules_file}...")
        
        if not os.path.exists(self.rules_file):
            print("❌ Rules file not found.")
            return

        parsed_rules = {
            "HTTP": [],
            "DNS": [],
            "GLOBAL": []
        }

        # Regex to extract SID, Message, and PCRE (Regex)
        # Example: msg:"ET EXPLOIT..."; pcre:"/regex/i"; sid:2000001;
        msg_regex = re.compile(r'msg:"([^"]+)"')
        sid_regex = re.compile(r'sid:(\d+)')
        pcre_regex = re.compile(r'pcre:"/([^/]+)/([a-z]*)"')
        content_regex = re.compile(r'content:"([^"]+)"') # Fallback if pcre is missing

        with open(self.rules_file, 'r', errors='ignore') as f:
            count = 0
            for line in f:
                if not line.startswith("alert") or "rev:" not in line:
                    continue
                
                # Filter for high-value only
                if not any(cat in line for cat in self.target_categories):
                    continue

                msg_match = msg_regex.search(line)
                sid_match = sid_regex.search(line)
                pcre_match = pcre_regex.search(line)
                content_match = content_regex.search(line)

                if not msg_match or not sid_match:
                    continue

                # Determine Risk Level based on category
                risk = "HIGH"
                if "EXPLOIT" in line or "MALWARE" in line: risk = "CRITICAL"
                elif "CNC" in line: risk = "CRITICAL"

                # Extract the best available regex/pattern
                final_regex = ""
                if pcre_match:
                    # Convert Suricata PCRE to Python Regex
                    pattern, flags = pcre_match.groups()
                    flag_str = "(?i)" if "i" in flags else ""
                    final_regex = flag_str + pattern
                elif content_match:
                    # Escape plain content for regex
                    final_regex = re.escape(content_match.group(1))

                if not final_regex: continue

                rule_obj = {
                    "sid": int(sid_match.group(1)),
                    "name": msg_match.group(1),
                    "regex": final_regex,
                    "risk_level": risk,
                    "category": "Community"
                }

                # Categorize by protocol
                if " dns " in line:
                    parsed_rules["DNS"].append(rule_obj)
                elif " http " in line or "80" in line or "443" in line:
                    parsed_rules["HTTP"].append(rule_obj)
                else:
                    parsed_rules["GLOBAL"].append(rule_obj)
                
                count += 1

        # Export to our systematic folders
        self._save(parsed_rules["HTTP"], "rules/protocol/http/http_signatures.json")
        self._save(parsed_rules["DNS"], "rules/protocol/dns/dns_signatures.json")
        
        print(f"[SigParser] Successfully converted {count} high-value signatures.")

    def _save(self, data, path):
        with open(path, 'w') as f:
            json.dump(data, f, indent=4)

if __name__ == "__main__":
    parser = SignatureParser()
    parser.parse_and_export()
