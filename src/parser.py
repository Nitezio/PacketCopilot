import subprocess
import os

class PacketParser:
    def __init__(self, tshark_path=r"C:\Program Files\Wireshark\tshark.exe"):
        self.tshark_path = tshark_path

    def extract_iocs(self, pcap_path):
        """
        Extracts IPs, DNS, and detailed stream data from a PCAP file.
        """
        if not os.path.exists(pcap_path):
            print(f"Error: File {pcap_path} not found.")
            return None

        unique_ips = set()
        dns_queries = set()
        ip_counts = {}
        
        # New: Detailed stream tracking
        # Structure: { ip: [ {proto, info, payload}, ... ] }
        ip_streams = {} 

        try:
            # Command to extract fields + protocol info + raw data
            cmd = [
                self.tshark_path,
                "-r", pcap_path,
                "-T", "fields",
                "-e", "ip.src",
                "-e", "ip.dst",
                "-e", "dns.qry.name",
                "-e", "tcp.payload",
                "-e", "udp.payload",
                "-e", "_ws.col.Protocol",
                "-e", "_ws.col.Info"
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            
            for line in result.stdout.splitlines():
                if not line.strip():
                    continue
                
                parts = line.split('\t')
                # parts: [src, dst, dns, tcp_hex, udp_hex, proto, info]
                
                src_ip = parts[0] if len(parts) > 0 else None
                dst_ip = parts[1] if len(parts) > 1 else None
                dns_name = parts[2] if len(parts) > 2 else None
                tcp_hex = parts[3] if len(parts) > 3 else ""
                udp_hex = parts[4] if len(parts) > 4 else ""
                proto = parts[5] if len(parts) > 5 else "Unknown"
                info = parts[6] if len(parts) > 6 else ""
                
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

                # Store stream info for both source and destination
                stream_entry = {
                    "Protocol": proto,
                    "Info": info,
                    "Payload": payload_content
                }

                if payload_content or info:
                    for ip in [src_ip, dst_ip]:
                        if ip:
                            if ip not in ip_streams:
                                ip_streams[ip] = []
                            # Avoid duplicates in the list
                            if stream_entry not in ip_streams[ip]:
                                ip_streams[ip].append(stream_entry)
                            
        except subprocess.CalledProcessError as e:
            print(f"TShark Error: {e.stderr}")
        except Exception as e:
            print(f"Error during parsing: {e}")

        return {
            "unique_ips": sorted(list(unique_ips)),
            "dns_queries": sorted(list(dns_queries)),
            "ip_counts": ip_counts,
            "streams": ip_streams
        }

if __name__ == "__main__":
    parser = PacketParser()
    print("PacketParser (Detailed Streams) initialized.")
