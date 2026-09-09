import requests
import json
import time
import os
from datetime import datetime

# Dates
START_DATE = "2026-08-08T00:00:00.000"
END_DATE = "2026-09-09T23:59:59.000"

def fetch_nvd_cves():
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "pubStartDate": START_DATE,
        "pubEndDate": END_DATE,
    }
    headers = {
        "User-Agent": "CTI-Research-Script"
    }
    
    all_cves = []
    start_index = 0
    results_per_page = 2000
    
    while True:
        params["startIndex"] = start_index
        print(f"Fetching NVD CVEs starting at index {start_index}...")
        try:
            response = requests.get(url, params=params, headers=headers)
            response.raise_for_status()
            data = response.json()
            
            cves = data.get("vulnerabilities", [])
            all_cves.extend(cves)
            
            total_results = data.get("totalResults", 0)
            print(f"Retrieved {len(cves)} CVEs. Total so far: {len(all_cves)} / {total_results}")
            
            if start_index + results_per_page >= total_results:
                break
            
            start_index += results_per_page
            time.sleep(6) # Sleep to respect rate limits (5 requests / 30 seconds without API key)
            
        except Exception as e:
            print(f"Error fetching NVD data: {e}")
            break
            
    print(f"Total CVEs collected: {len(all_cves)}")
    with open("data/nvd_cves.json", "w", encoding='utf-8') as f:
        json.dump(all_cves, f, indent=2)

if __name__ == "__main__":
    os.makedirs("data", exist_ok=True)
    fetch_nvd_cves()
