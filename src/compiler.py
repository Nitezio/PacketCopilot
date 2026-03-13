import yara
import os
import json
import re

class ForensicCompiler:
    def __init__(self, rules_dir="rules", compiled_dir="rules/compiled"):
        self.rules_dir = rules_dir
        self.compiled_dir = compiled_dir
        if not os.path.exists(self.compiled_dir):
            os.makedirs(self.compiled_dir)

    def compile_all(self):
        print("[Compiler] Starting professional rules compilation...")
        yara_path = self.compile_yara()
        et_path = self.compile_et_open()
        return yara_path, et_path

    def compile_yara(self):
        """
        Compiles the pre-flattened master YARA ruleset.
        """
        flat_rule_path = os.path.join(self.rules_dir, "global", "flattened_malware.yar")
        
        if not os.path.exists(flat_rule_path):
            print(f"[Compiler] Error: Flattened rules not found at {flat_rule_path}")
            return None

        try:
            # Load the single flattened file
            compiled_rules = yara.compile(filepath=flat_rule_path)
            output_path = os.path.join(self.compiled_dir, "master_forensics.yarc")
            compiled_rules.save(output_path)
            print(f"[Compiler] YARA: Successfully baked the FULL community ruleset into binary.")
            return output_path
        except Exception as e:
            print(f"[Compiler] YARA Error: {e}")
            return None

    def compile_et_open(self):
        """
        Validates and optimizes the JSON regex signatures, filtering out incompatible PCRE.
        """
        all_et_rules = []
        for root, dirs, files in os.walk(os.path.join(self.rules_dir, "protocol")):
            for file in files:
                if file.endswith("_signatures.json"):
                    try:
                        with open(os.path.join(root, file), 'r') as f:
                            rules = json.load(f)
                            for r in rules:
                                try:
                                    # Filter out Suricata-specific extensions like (?< or (?P
                                    # Python's 're' module is strict. 
                                    clean_regex = r['regex']
                                    if "(?<" in clean_regex or "(?P<" in clean_regex:
                                        continue # Skip advanced PCRE not compatible with Python
                                    
                                    re.compile(clean_regex)
                                    r['protocol'] = os.path.basename(root).upper()
                                    all_et_rules.extend(rules)
                                except: continue 
                    except Exception as e:
                        print(f"[Compiler] ET Error in {file}: {e}")

        # Limit to top 5000 rules to prevent memory bloat in Streamlit
        optimized_subset = all_et_rules[:5000]
        output_path = os.path.join(self.compiled_dir, "network_signatures_optimized.json")
        with open(output_path, 'w') as f:
            json.dump(optimized_subset, f, indent=4)
        
        print(f"[Compiler] ET Open: Optimized {len(optimized_subset)} network signatures (filtered for Python compatibility).")
        return output_path

if __name__ == "__main__":
    compiler = ForensicCompiler()
    compiler.compile_all()
