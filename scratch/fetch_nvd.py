import requests
import json
from datetime import datetime, timedelta

def fetch_cves():
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "pubStartDate": "2026-08-08T00:00:00.000",
        "pubEndDate": "2026-09-09T23:59:59.000",
        "cvssV3Severity": "CRITICAL"
    }
    headers = {
        "User-Agent": "CTI-Research-Script"
    }
    try:
        response = requests.get(url, params=params, headers=headers)
        response.raise_for_status()
        data = response.json()
        print(f"Found {data.get('totalResults', 0)} critical CVEs published between 08 Aug 2026 and 09 Sep 2026.")
        
        # Save first few for inspection
        with open("nvd_sample.json", "w") as f:
            json.dump(data.get("vulnerabilities", [])[:5], f, indent=2)
            
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    fetch_cves()
