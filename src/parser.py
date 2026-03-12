import subprocess
import os
import yara
import re
import json
import datetime

class PacketParser:
    def __init__(self, tshark_path=r"C:\Program Files\Wireshark\tshark.exe"):
        self.tshark_path = tshark_path
        self.yara_engine = self._load_compiled_yara()
        self.rule_registry = self._load_protocol_registry()

    def _load_compiled_yara(self):
        """Loads the pre-compiled master binary for YARA."""
        yarc_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "rules", "compiled", "master_forensics.yarc")
        if os.path.exists(yarc_path):
            try:
                return yara.load(yarc_path)
            except Exception as e:
                print(f"[YARA] Load Error: {e}")
        return None

    def _load_protocol_registry(self):
        """Organizes optimized ET signatures into a Protocol-Gated Registry."""
        registry = {}
        json_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "rules", "compiled", "network_signatures_optimized.json")
        if os.path.exists(json_path):
            try:
                with open(json_path, 'r') as f:
                    rules = json.load(f)
                    for rule in rules:
                        proto = rule.get('protocol', 'GLOBAL')
                        if proto not in registry:
                            registry[proto] = []
                        # Compile pattern for execution speed
                        rule['pattern'] = re.compile(rule['regex'])
                        registry[proto].append(rule)
            except Exception as e:
                print(f"[Registry] Load Error: {e}")
        return registry

    def _analyze_payload_risk(self, payload, info, status, protocol):
        """
        Gated Risk Engine: Only scans relevant rule subsets based on protocol.
        """
        if not payload and not info: return "🟢 LOW"

        # 1. Global YARA Scan (Files/Malware - Always runs)
        if self.yara_engine and payload:
            try:
                matches = self.yara_engine.match(data=payload.encode('utf-8', errors='ignore'))
                if matches:
                    top = matches[0]
                    return f"🔥 {top.meta.get('risk_level', 'HIGH')} (YARA: {top.rule})"
            except: pass

        # 2. Contextual ET Open Scan (Protocol Gating)
        # We check both the specific protocol registry and the 'GLOBAL' registry
        target_rules = self.rule_registry.get(protocol.upper(), []) + self.rule_registry.get('GLOBAL', [])
        
        for rule in target_rules:
            if (payload and rule['pattern'].search(payload)) or (info and rule['pattern'].search(info)):
                return f"🛡️ {rule['risk_level']} ({rule['name']})"

        # 3. Behavioral Fallback
        if status == "Malicious": return "🟠 HIGH (Known Malicious IP)"
            
        return "🟢 LOW"

    def extract_iocs(self, pcap_path, ip_reputations={}):
        """Extracts forensic data using the optimized Gated Engine."""
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

                # --- Forensic Risk Scoring (Gated Engine) ---
                dest_status = ip_reputations.get(dst_ip, "Clean")
                dns_status = ip_reputations.get(dns_name, "Clean")
                
                risk_label = self._analyze_payload_risk(payload_content, info, dest_status, proto)
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
    print("PacketParser (Registry-Based Gated Engine) initialized.")
