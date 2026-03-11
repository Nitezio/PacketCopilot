import requests
import os

class IntelValidator:
    def __init__(self, api_key=None):
        self.api_key = api_key or os.getenv("VT_API_KEY")
        self.base_url = "https://www.virustotal.com/api/v3"

    def get_ip_report(self, ip_address):
        """
        Queries VirusTotal for an IP address report.
        """
        return self._get_report("ip_addresses", ip_address)

    def get_domain_report(self, domain):
        """
        Queries VirusTotal for a domain report.
        """
        return self._get_report("domains", domain)

    def _get_report(self, resource_type, indicator):
        if not self.api_key:
            import random
            is_malicious = "malicious" in indicator.lower() or random.choice([True, False, False, False])
            return {
                "malicious_count": 15 if is_malicious else 0,
                "total_engines": 94,
                "status": "Malicious" if is_malicious else "Clean",
                "full_report": {"mock": True, "indicator": indicator, "type": resource_type}
            }

        headers = {"x-apikey": self.api_key}
        try:
            response = requests.get(f"{self.base_url}/{resource_type}/{indicator}", headers=headers)
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
            else:
                return {"error": f"API Error: {response.status_code}", "status": "Error", "full_report": {}}
        except Exception as e:
            return {"error": str(e), "status": "Exception", "full_report": {}}

if __name__ == "__main__":
    validator = IntelValidator()
    print(f"Mocking IP Report: {validator.get_ip_report('8.8.8.8')}")
