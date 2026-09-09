import requests
import json
import os
from datetime import datetime

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

def fetch_kev():
    print("Fetching CISA KEV catalog...")
    try:
        response = requests.get(KEV_URL)
        response.raise_for_status()
        data = response.json()
        
        vulnerabilities = data.get("vulnerabilities", [])
        
        # Filter for dates between 08 Aug 2026 and 09 Sep 2026
        start_date = datetime.strptime("2026-08-08", "%Y-%m-%d").date()
        end_date = datetime.strptime("2026-09-09", "%Y-%m-%d").date()
        
        filtered_kev = []
        for vuln in vulnerabilities:
            date_added_str = vuln.get("dateAdded")
            if date_added_str:
                date_added = datetime.strptime(date_added_str, "%Y-%m-%d").date()
                if start_date <= date_added <= end_date:
                    filtered_kev.append(vuln)
                    
        print(f"Total vulnerabilities added to KEV in timeframe: {len(filtered_kev)}")
        
        with open("data/cisa_kev.json", "w", encoding="utf-8") as f:
            json.dump(filtered_kev, f, indent=2)
            
    except Exception as e:
        print(f"Error fetching KEV: {e}")

if __name__ == "__main__":
    os.makedirs("data", exist_ok=True)
    fetch_kev()
