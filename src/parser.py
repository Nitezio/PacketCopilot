import subprocess
import os

class PacketParser:
    def __init__(self, tshark_path=r"C:\Program Files\Wireshark\tshark.exe"):
        self.tshark_path = tshark_path

    def extract_iocs(self, pcap_path):
        """
        Extracts unique IPs, DNS queries, and sample payloads from a PCAP file.
        """
        if not os.path.exists(pcap_path):
            print(f"Error: File {pcap_path} not found.")
            return None

        unique_ips = set()
        dns_queries = set()
        payload_samples = {} # Mapping IP to a sample of its payload
        ip_counts = {} # Tracking packet frequency for visualization

        try:
            # Command to extract fields + raw data (hex)
            cmd = [
                self.tshark_path,
                "-r", pcap_path,
                "-T", "fields",
                "-e", "ip.src",
                "-e", "ip.dst",
                "-e", "dns.qry.name",
                "-e", "tcp.payload",
                "-e", "udp.payload"
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            
            for line in result.stdout.splitlines():
                if not line.strip():
                    continue
                
                parts = line.split('\t')
                
                src_ip = parts[0] if len(parts) > 0 else None
                dst_ip = parts[1] if len(parts) > 1 else None
                dns_name = parts[2] if len(parts) > 2 else None
                tcp_payload = parts[3] if len(parts) > 3 else ""
                udp_payload = parts[4] if len(parts) > 4 else ""
                
                if src_ip: 
                    unique_ips.add(src_ip)
                    ip_counts[src_ip] = ip_counts.get(src_ip, 0) + 1
                if dst_ip: 
                    unique_ips.add(dst_ip)
                    ip_counts[dst_ip] = ip_counts.get(dst_ip, 0) + 1
                
                if dns_name:
                    for q in dns_name.split(','):
                        if q.strip(): dns_queries.add(q.strip())
                
                # Capture and truncate payload (1KB limit)
                raw_hex = tcp_payload or udp_payload
                if raw_hex:
                    # Clean the hex string (remove colons if present)
                    clean_hex = raw_hex.replace(':', '')
                    try:
                        decoded = bytes.fromhex(clean_hex).decode('utf-8', errors='ignore')
                        payload_content = decoded[:1000]
                    except:
                        payload_content = clean_hex[:1000] # Fallback to raw hex
                    
                    # Associate this payload with BOTH source and destination
                    # This ensures the "Middle Pane" shows data for either side of the talk
                    if src_ip and src_ip not in payload_samples:
                        payload_samples[src_ip] = payload_content
                    if dst_ip and dst_ip not in payload_samples:
                        payload_samples[dst_ip] = payload_content
                            
        except subprocess.CalledProcessError as e:
            print(f"TShark Error: {e.stderr}")
        except Exception as e:
            print(f"Error during parsing: {e}")

        return {
            "unique_ips": sorted(list(unique_ips)),
            "dns_queries": sorted(list(dns_queries)),
            "payloads": payload_samples,
            "ip_counts": ip_counts
        }

if __name__ == "__main__":
    parser = PacketParser()
    print("PacketParser (Subprocess Edition) initialized.")
