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
        """
        Orchestrates the compilation of YARA and Network signatures.
        """
        print("[Compiler] Starting professional rules compilation...")
        yara_path = self.compile_yara()
        et_path = self.compile_et_open()
        return yara_path, et_path

    def compile_yara(self):
        """
        Compiles all .yar files into a single binary blob.
        """
        rule_map = {}
        # Collect all YARA files from global and protocol folders
        for root, dirs, files in os.walk(self.rules_dir):
            for file in files:
                if file.endswith(".yar"):
                    namespace = os.path.basename(root)
                    full_path = os.path.join(root, file)
                    rule_map[f"{namespace}_{file}"] = full_path

        if not rule_map:
            print("[Compiler] No YARA rules found.")
            return None

        try:
            compiled_rules = yara.compile(filepaths=rule_map)
            output_path = os.path.join(self.compiled_dir, "master_forensics.yarc")
            compiled_rules.save(output_path)
            print(f"[Compiler] YARA: Successfully baked {len(rule_map)} rule files into binary.")
            return output_path
        except Exception as e:
            print(f"[Compiler] YARA Error: {e}")
            return None

    def compile_et_open(self):
        """
        Validates and optimizes the JSON regex signatures.
        """
        all_et_rules = []
        for root, dirs, files in os.walk(os.path.join(self.rules_dir, "protocol")):
            for file in files:
                if file.endswith("_signatures.json"):
                    try:
                        with open(os.path.join(root, file), 'r') as f:
                            rules = json.load(f)
                            # Verify regex syntax before finishing
                            for r in rules:
                                re.compile(r['regex'])
                                r['protocol'] = os.path.basename(root).upper()
                            all_et_rules.extend(rules)
                    except Exception as e:
                        print(f"[Compiler] ET Error in {file}: {e}")

        output_path = os.path.join(self.compiled_dir, "network_signatures_optimized.json")
        with open(output_path, 'w') as f:
            json.dump(all_et_rules, f, indent=4)
        
        print(f"[Compiler] ET Open: Optimized {len(all_et_rules)} network signatures.")
        return output_path

if __name__ == "__main__":
    compiler = ForensicCompiler()
    compiler.compile_all()
