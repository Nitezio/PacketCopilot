import requests
import os
import tarfile
import io
import re
import yara

class RulesDownloader:
    def __init__(self, base_dir="rules"):
        self.base_dir = base_dir
        self.sources = {
            "yara": [
                {"name": "master_malware.yar", "url": "https://raw.githubusercontent.com/YARA-Rules/rules/master/malware_index.yar"}
            ],
            "et_open": [
                {"name": "emerging-all.rules.tar.gz", "url": "http://rules.emergingthreats.net/open/suricata-6.0.8/emerging-all.rules.tar.gz"}
            ]
        }

    def download_all(self):
        print("[Downloader] Starting FULL professional rules sync...")
        os.makedirs(os.path.join(self.base_dir, "global"), exist_ok=True)
        os.makedirs(os.path.join(self.base_dir, "protocol", "http"), exist_ok=True)

        for source in self.sources["yara"]:
            dest = os.path.join(self.base_dir, "global", source["name"])
            if self._fetch(source["url"], dest):
                self._fetch_yara_includes(dest)

        for source in self.sources["et_open"]:
            self._fetch_and_extract_tar(source["url"])
            
        self.flatten_yara()

    def _fetch_yara_includes(self, master_file):
        print("[Downloader] Parsing YARA index for sub-rules...")
        base_url = "https://raw.githubusercontent.com/YARA-Rules/rules/master/"
        with open(master_file, 'r') as f:
            content = f.read()
        includes = re.findall(r'include "([^"]+)"', content)
        for inc in includes:
            clean_inc = inc.replace("./", "")
            url = base_url + clean_inc
            dest = os.path.join(self.base_dir, "global", os.path.basename(clean_inc))
            self._fetch(url, dest)

    def flatten_yara(self):
        """
        Validates each rule file and merges only the functional ones.
        """
        print("[Downloader] Validating and Flattening YARA rules...")
        output_file = os.path.join(self.base_dir, "global", "flattened_malware.yar")
        global_dir = os.path.join(self.base_dir, "global")
        
        valid_count = 0
        with open(output_file, 'w', encoding='utf-8') as outfile:
            for filename in sorted(os.listdir(global_dir)):
                if filename.endswith(".yar") and filename not in ["master_malware.yar", "flattened_malware.yar"]:
                    filepath = os.path.join(global_dir, filename)
                    
                    # --- Strict Validation Check ---
                    try:
                        # Attempt to compile just this one file to check for syntax errors
                        yara.compile(filepath=filepath)
                        
                        # If success, merge it
                        with open(filepath, 'r', encoding='utf-8', errors='ignore') as infile:
                            outfile.write(f"\n/* --- {filename} --- */\n")
                            for line in infile:
                                if not line.strip().startswith("include"):
                                    outfile.write(line)
                        valid_count += 1
                    except Exception:
                        # Skip files with incompatible syntax
                        continue
        
        print(f"  ✅ Successfully merged {valid_count} high-quality rule files into {output_file}")

    def _fetch(self, url, dest):
        try:
            r = requests.get(url, timeout=15)
            if r.status_code == 200:
                with open(dest, 'wb') as f:
                    f.write(r.content)
                return True
        except: pass
        return False

    def _fetch_and_extract_tar(self, url):
        try:
            r = requests.get(url, timeout=60)
            if r.status_code == 200:
                with tarfile.open(fileobj=io.BytesIO(r.content), mode="r:gz") as tar:
                    for member in tar.getmembers():
                        if member.name.endswith(".rules"):
                            member.name = os.path.basename(member.name)
                            tar.extract(member, path=os.path.join(self.base_dir, "protocol", "http"))
        except: pass

if __name__ == "__main__":
    downloader = RulesDownloader()
    downloader.download_all()
