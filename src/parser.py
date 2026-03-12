import subprocess
import os
import yara
import re
import json

class PacketParser:
    def __init__(self, tshark_path=r"C:\Program Files\Wireshark\tshark.exe"):
        self.tshark_path = tshark_path
        self.yara_rules = self._load_yara_rules()
        self.et_rules = self._load_et_rules()

    def _load_yara_rules(self):
        """Compiles YARA rules from the local rules directory."""
        rule_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "rules", "yara", "forensic_rules.yar")
        if os.path.exists(rule_path):
            try: return yara.compile(filepath=rule_path)
            except Exception as e: print(f"[YARA] Compilation Error: {e}")
        return None

    def _load_et_rules(self):
        """Loads ET Open inspired network signatures from JSON."""
        et_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "rules", "et_open", "network_signatures.json")
        if os.path.exists(et_path):
            try:
                with open(et_path, 'r') as f:
                    rules = json.load(f)
                    # Pre-compile regex for performance
                    for rule in rules:
                        rule['pattern'] = re.compile(rule['regex'])
                    return rules
            except Exception as e: print(f"[ET Open] Load Error: {e}")
        return []

    def _analyze_payload_risk(self, payload, info, status):
        """
        Triple-Layer Risk Engine: YARA (Malware) + ET Open (Network) + Heuristics.
        """
        # 1. YARA Signature Check (Best for files/scripts)
        if self.yara_rules and payload:
            try:
                matches = self.yara_rules.match(data=payload.encode('utf-8', errors='ignore'))
                if matches:
                    top = matches[0]
                    return f"🔥 {top.meta.get('risk_level', 'HIGH')} (YARA: {top.rule})"
            except: pass

        # 2. ET Open Network Signature Check (Best for protocols/exploits)
        for rule in self.et_rules:
            # Match against payload OR info field
            if (payload and rule['pattern'].search(payload)) or (info and rule['pattern'].search(info)):
                return f"🛡️ {rule['risk_level']} ({rule['name']})"

        # 3. Heuristic Fallback
        if not payload and not info: return "🟢 LOW"
        
        payload_lower = payload.lower()
        if "mz" in payload[:4]: return "🔥 CRITICAL (Executable File Header)"
        if status == "Malicious": return "🟠 HIGH (Known Malicious IP)"
            
        return "🟢 LOW"

    def extract_iocs(self, pcap_path, ip_reputations={}):
        """Extracts forensic data with Triple-Layer Risk Scoring."""
        if not os.path.exists(pcap_path): return None

        unique_ips, dns_queries = set(), set()
        ip_counts, ip_streams, timeline_events = {}, {}, []

        try:
            cmd = [
                self.tshark_path, "-r", pcap_path, "-T", "fields",
                "-e", "frame.time_epoch", "-e", "ip.src", "-e", "ip.dst",
                "-e", "dns.qry.name", "-e", "tcp.payload", "-e", "udp.payload",
                "-e", "_ws.col.Protocol", "-e", "_ws.col.Info",
                "-e", "tcp.srcport", "-e", "tcp.dstport", "-e", "udp.srcport", "-e", "udp.dstport"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            
            import datetime
            for line in result.stdout.splitlines():
                if not line.strip(): continue
                parts = line.split('\t')
                
                epoch = float(parts[0]) if len(parts) > 0 and parts[0] else 0.0
                dt = datetime.datetime.fromtimestamp(epoch)
                date_str, time_str = dt.strftime('%Y-%m-%d'), dt.strftime('%H:%M')

                src_ip = parts[1].split(':')[0] if len(parts) > 1 and parts[1] else None
                dst_ip = parts[2].split(':')[0] if len(parts) > 2 and parts[2] else None
                dns_name = parts[3] if len(parts) > 3 else None
                tcp_hex = parts[4] if len(parts) > 4 else ""
                udp_hex = parts[5] if len(parts) > 5 else ""
                proto = parts[6] if len(parts) > 6 else "Unknown"
                info = parts[7] if len(parts) > 7 else ""
                src_port = parts[8] or parts[10] or ""
                dst_port = parts[9] or parts[11] or ""
                
                if src_ip: 
                    unique_ips.add(src_ip)
                    ip_counts[src_ip] = ip_counts.get(src_ip, 0) + 1
                if dst_ip: 
                    unique_ips.add(dst_ip)
                    ip_counts[dst_ip] = ip_counts.get(dst_ip, 0) + 1
                if dns_name:
                    for q in dns_name.split(','):
                        if q.strip(): dns_queries.add(q.strip())
                
                raw_hex = tcp_hex or udp_hex
                payload_content = ""
                if raw_hex:
                    try:
                        payload_content = bytes.fromhex(raw_hex.replace(':', '')).decode('utf-8', errors='ignore')[:1000]
                    except: payload_content = raw_hex[:1000]

                # --- Forensic Risk Scoring (YARA + ET + Heuristics) ---
                dest_status = ip_reputations.get(dst_ip, "Clean")
                dns_status = ip_reputations.get(dns_name, "Clean")
                
                risk_label = self._analyze_payload_risk(payload_content, info, dest_status)
                if dns_status == "Malicious": risk_label = "🟠 HIGH (Malicious Domain Query)"

                stream_entry = {
                    "Date": date_str, "Time": time_str, "Protocol": proto, "Info": info,
                    "Payload": payload_content, "Source": src_ip, "SrcPort": src_port,
                    "Destination": dst_ip, "DstPort": dst_port, "Risk": risk_label
                }

                if "LOW" not in risk_label or payload_content:
                    timeline_events.append(stream_entry)

                if payload_content or info:
                    for ip in [src_ip, dst_ip]:
                        if ip:
                            if ip not in ip_streams: ip_streams[ip] = []
                            if stream_entry not in ip_streams[ip]: ip_streams[ip].append(stream_entry)
                            
        except Exception as e: print(f"Error during parsing: {e}")

        return {
            "unique_ips": sorted(list(unique_ips)),
            "dns_queries": sorted(list(dns_queries)),
            "ip_counts": ip_counts,
            "streams": ip_streams,
            "timeline": timeline_events
        }

if __name__ == "__main__":
    parser = PacketParser()
    print("PacketParser (Triple-Layer Risk Engine) initialized.")
