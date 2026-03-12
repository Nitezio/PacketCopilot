import requests
import os
import whois
import time
import ipaddress
from ipwhois import IPWhois

class IntelValidator:
    # Class-level variables for global rate limiting
    _last_request_time = 0
    _request_delay = 15.5  # Default for Free Tier (4 RPM + safety buffer)

    def __init__(self, api_key=None):
        self.api_key = api_key or os.getenv("VT_API_KEY")
        self.base_url = "https://www.virustotal.com/api/v3"
        # If we have a key, try to auto-configure once
        if self.api_key:
            self.auto_configure_rate_limit()

    def auto_configure_rate_limit(self):
        """
        Queries VT to find the actual rate limit and sets the delay dynamically.
        """
        headers = {"x-apikey": self.api_key}
        try:
            # We use the current user endpoint to find quotas
            # This endpoint itself counts as a request, so we are careful.
            response = requests.get(f"{self.base_url}/users/{self.api_key}", headers=headers)
            if response.status_code == 200:
                data = response.json()
                quotas = data.get('data', {}).get('attributes', {}).get('quotas', {})
                rpm = quotas.get('api_requests_per_minute', {}).get('allowed', 4)
                
                if rpm > 0:
                    # Calculate delay: 60 seconds / RPM. 
                    # Add 0.5s buffer to prevent race conditions on the server side.
                    IntelValidator._request_delay = (60.0 / rpm) + 0.5
                    print(f"[Intel] Auto-configured rate limit: {rpm} RPM (Delay: {IntelValidator._request_delay}s)")
        except Exception:
            # Fallback to safe free tier defaults
            IntelValidator._request_delay = 15.5

    def is_private_ip(self, ip_addr):
        """Checks if an IP address is private/internal."""
        try:
            return ipaddress.ip_address(ip_addr).is_private
        except ValueError:
            return False

    def get_whois_data(self, indicator, is_ip=False):
        """
        Gathers Registrar/ASN info using local libraries and provides a whois.com link.
        """
        details = {
            "Provider": "Internal/Private" if is_ip and self.is_private_ip(indicator) else "Unknown",
            "Link": f"https://www.whois.com/whois/{indicator}"
        }
        
        if is_ip and self.is_private_ip(indicator):
            return details

        try:
            if is_ip:
                obj = IPWhois(indicator)
                res = obj.lookup_rdap(depth=1)
                details["Provider"] = res.get('asn_description', "Unknown ASN")
            else:
                import socket
                socket.setdefaulttimeout(5)
                w = whois.whois(indicator)
                details["Provider"] = w.registrar if w.registrar else "Unknown Registrar"
        except Exception:
            details["Provider"] = "Lookup Failed"
            
        return details

    def get_ip_report(self, ip_address):
        return self._get_report("ip_addresses", ip_address)

    def get_domain_report(self, domain):
        return self._get_report("domains", domain)

    def _get_report(self, resource_type, indicator):
        # 1. Handle Private IPs
        if resource_type == "ip_addresses" and self.is_private_ip(indicator):
            return {
                "malicious_count": 0,
                "total_engines": 0,
                "status": "Clean (Private IP)",
                "full_report": {"note": "Internal Address"}
            }

        # 2. Require API Key for External Indicators
        if not self.api_key:
            return {
                "malicious_count": 0,
                "total_engines": 0,
                "status": "API Key Required",
                "full_report": {}
            }

        # 3. Real API Request with DYNAMIC Rate Limiting
        now = time.time()
        elapsed = now - IntelValidator._last_request_time
        if elapsed < IntelValidator._request_delay:
            time.sleep(IntelValidator._request_delay - elapsed)

        headers = {"x-apikey": self.api_key}
        try:
            response = requests.get(f"{self.base_url}/{resource_type}/{indicator}", headers=headers)
            IntelValidator._last_request_time = time.time()

            if response.status_code == 200:
                data = response.json()
                stats = data['data']['attributes']['last_analysis_stats']
                malicious = stats.get('malicious', 0)
                return {
                    "malicious_count": malicious,
                    "total_engines": sum(stats.values()),
                    "status": "Malicious" if malicious > 0 else "Clean",
                    "full_report": data
                }
            elif response.status_code == 429:
                return {"error": "API Rate Limit Exceeded", "status": "RateLimited", "full_report": {}}
            else:
                return {"error": f"API Error: {response.status_code}", "status": "Error", "full_report": {}}
        except Exception as e:
            return {"error": str(e), "status": "Exception", "full_report": {}}
