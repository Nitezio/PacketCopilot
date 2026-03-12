import subprocess
import os
import yara

class PacketParser:
    def __init__(self, tshark_path=r"C:\Program Files\Wireshark\tshark.exe"):
        self.tshark_path = tshark_path
        self.yara_rules = self._load_yara_rules()

    def _load_yara_rules(self):
        """
        Compiles YARA rules from the local rules directory.
        """
        rule_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "rules", "yara", "forensic_rules.yar")
        if os.path.exists(rule_path):
            try:
                return yara.compile(filepath=rule_path)
            except Exception as e:
                print(f"[YARA] Compilation Error: {e}")
        return None

    def _analyze_payload_risk(self, payload, info, status):
        """
        Hybrid Risk Engine: Combines YARA signatures with manual heuristics.
        """
        # 1. YARA Signature Check (Highest Accuracy)
        if self.yara_rules and payload:
            try:
                # Scan payload (bytes)
                matches = self.yara_rules.match(data=payload.encode('utf-8', errors='ignore'))
                if matches:
                    # Get the match with the highest risk from meta
                    top_match = matches[0]
                    risk = top_match.meta.get("risk_level", "HIGH")
                    desc = top_match.meta.get("description", "Malicious Signature Detected")
                    return f"🔥 {risk} ({top_match.rule}: {desc})"
            except Exception as e:
                print(f"[YARA] Scan Error: {e}")

        # 2. Heuristic Fallback (Keyword matching)
        payload_lower = payload.lower()
        info_lower = info.lower()
        
        if "mz" in payload[:4] or "this program cannot be run" in payload_lower:
            return "🔥 CRITICAL (Executable File Header)"
        if any(term in payload_lower for term in ["powershell", "cmd.exe", "whoami", "curl", "wget", ".exe", ".sh"]):
            return "🔴 HIGH (Command Execution Keywords)"
        if status == "Malicious":
            return "🟠 HIGH (Known Malicious IP)"
            
        if any(term in info_lower for term in ["login", "admin", "password", "upload"]):
            return "🟡 MEDIUM (Sensitive Action)"
            
        return "🟢 LOW"

    def extract_iocs(self, pcap_path, ip_reputations={}):
        """
        Extracts detailed forensic data including YARA and Heuristic Risk Scoring.
        """
        if not os.path.exists(pcap_path):
            return None

        unique_ips = set()
        dns_queries = set()
        ip_counts = {}
        ip_streams = {} 
        timeline_events = []

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
                
                # frame.time_epoch
                epoch = float(parts[0]) if len(parts) > 0 and parts[0] else 0.0
                dt = datetime.datetime.fromtimestamp(epoch)
                date_str = dt.strftime('%Y-%m-%d')
                time_str = dt.strftime('%H:%M')

                src_raw = parts[1] if len(parts) > 1 else None
                dst_raw = parts[2] if len(parts) > 2 else None
                
                # Normalize IPs
                src_ip = src_raw.split(':')[0] if src_raw else None
                dst_ip = dst_raw.split(':')[0] if dst_raw else None
                
                dns_name = parts[3] if len(parts) > 3 else None
                tcp_hex = parts[4] if len(parts) > 4 else ""
                udp_hex = parts[5] if len(parts) > 5 else ""
                proto = parts[6] if len(parts) > 6 else "Unknown"
                info = parts[7] if len(parts) > 7 else ""
                
                # Extract Ports
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
                
                # Payload processing
                raw_hex = tcp_hex or udp_hex
                payload_content = ""
                if raw_hex:
                    clean_hex = raw_hex.replace(':', '')
                    try:
                        decoded = bytes.fromhex(clean_hex).decode('utf-8', errors='ignore')
                        payload_content = decoded[:1000]
                    except:
                        payload_content = clean_hex[:1000]

                # --- Forensic Risk Scoring (YARA + Heuristics) ---
                dest_status = ip_reputations.get(dst_ip, "Clean")
                dns_status = ip_reputations.get(dns_name, "Clean")
                
                risk_label = self._analyze_payload_risk(payload_content, info, dest_status)
                if dns_status == "Malicious":
                    risk_label = "🟠 HIGH (Malicious Domain Query)"

                stream_entry = {
                    "Date": date_str,
                    "Time": time_str,
                    "Protocol": proto,
                    "Info": info,
                    "Payload": payload_content,
                    "Source": src_ip,
                    "SrcPort": src_port,
                    "Destination": dst_ip,
                    "DstPort": dst_port,
                    "Risk": risk_label
                }

                # Filter timeline to significant events
                if "LOW" not in risk_label or payload_content:
                    timeline_events.append(stream_entry)

                if payload_content or info:
                    for ip in [src_ip, dst_ip]:
                        if ip:
                            if ip not in ip_streams: ip_streams[ip] = []
                            if stream_entry not in ip_streams[ip]: ip_streams[ip].append(stream_entry)
                            
        except Exception as e:
            print(f"Error during parsing: {e}")

        return {
            "unique_ips": sorted(list(unique_ips)),
            "dns_queries": sorted(list(dns_queries)),
            "ip_counts": ip_counts,
            "streams": ip_streams,
            "timeline": timeline_events
        }

if __name__ == "__main__":
    parser = PacketParser()
    print("PacketParser (YARA-Enhanced) initialized.")
