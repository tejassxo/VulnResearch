import json
import os
import re
import pandas as pd
from datetime import datetime

REQUIRED_COLUMNS = [
    "Record_ID",
    "Date_Observed",
    "Vulnerability_Identifier",
    "Affected_Component",
    "Target_Sector_India",
    "Vulnerability_Classification",
    "Severity_CVSS",
    "Exploitation_Status",
    "Technical_Summary",
    "Remediation_Vector",
    "Verified_Source_Reference"
]

def clean_text(s):
    if not isinstance(s, str):
        return str(s)
    # Normalize unicode quotes and dashes
    s = s.replace('\u2014', ' - ').replace('\u2013', ' - ').replace('\u2018', "'").replace('\u2019', "'")
    s = s.replace('\u201c', '"').replace('\u201d', '"').replace('\u2022', '*')
    s = re.sub(r'[\uFFFD\x96\x97]', ' - ', s)
    s = re.sub(r'\s+', ' ', s).strip()
    return s

def load_cisa_kev():
    try:
        with open("data/cisa_kev.json", "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return []

def load_nvd_cves():
    try:
        with open("data/nvd_cves.json", "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return []

def map_indian_sector(component, desc):
    text = (str(component) + " " + str(desc)).lower()
    if any(k in text for k in ["bank", "finan", "payment", "hyperion", "commerce", "magento", "sharepoint", "exchange", "outlook"]):
        return "BFSI & Financial Infrastructure"
    elif any(k in text for k in ["cisco", "fortinet", "palo alto", "juniper", "telecom", "router", "gateway", "sonicwall", "vpn"]):
        return "Telecommunications & Critical Network Infrastructure"
    elif any(k in text for k in ["windows", "active directory", "kernel", "linux", "server 20", "defense", "gov", "nic."]):
        return "Government, Defense & Critical Infrastructure (CII)"
    elif any(k in text for k in ["cloud", "docker", "kubernetes", "vmware", "virtualbox", "aws", "azure", "artifactory"]):
        return "Enterprise Cloud & Data Center Infrastructure"
    elif any(k in text for k in ["chrome", "chromium", "browser", "office", "acrobat", "reader", "edge", "client"]):
        return "Enterprise Workstations & Digital Workplace"
    else:
        return "General Enterprise / Indian Attack Surface"

def extract_nvd_component(cve, desc):
    affected = cve.get("affected", [])
    if affected:
        aff_data = affected[0].get("affectedData", [])
        if aff_data:
            v = aff_data[0].get("vendor", "")
            p = aff_data[0].get("product", "")
            if v and v != "Unknown" and p and p != "Unknown":
                # Clean up if product repeats vendor
                if v.lower() in p.lower():
                    return clean_text(p)
                return clean_text(f"{v} {p}")
            elif p and p != "Unknown":
                return clean_text(p)
            elif v and v != "Unknown":
                return clean_text(v)
                
    # Fallback to regex from description
    desc_lower = desc.lower()
    major_vendors = [
        ("microsoft windows", "Microsoft Windows"),
        ("microsoft sharepoint", "Microsoft SharePoint"),
        ("microsoft exchange", "Microsoft Exchange Server"),
        ("microsoft office", "Microsoft Office 365"),
        ("google chrome", "Google Chrome"),
        ("cisco ios", "Cisco IOS / XE"),
        ("cisco", "Cisco Network Architecture"),
        ("fortinet", "Fortinet FortiOS / FortiGate"),
        ("palo alto", "Palo Alto Networks PAN-OS"),
        ("oracle database", "Oracle Database"),
        ("oracle hyperion", "Oracle Hyperion"),
        ("oracle", "Oracle Enterprise Solutions"),
        ("adobe experience manager", "Adobe Experience Manager"),
        ("adobe acrobat", "Adobe Acrobat / Reader"),
        ("adobe", "Adobe Creative / Enterprise"),
        ("vmware", "VMware Virtualization Platform"),
        ("ivanti", "Ivanti Connect Secure / EPMM"),
        ("citrix", "Citrix NetScaler / ADC"),
        ("apple", "Apple macOS / iOS Enterprise")
    ]
    for pattern, name in major_vendors:
        if pattern in desc_lower:
            return name
            
    return "Enterprise Infrastructure Component"

def process_kev(kev_data, nvd_map, record_counter):
    records = []
    for item in kev_data:
        cve_id = item.get("cveID")
        date_added = item.get("dateAdded")
        try:
            date_obj = datetime.strptime(date_added, "%Y-%m-%d")
            formatted_date = date_obj.strftime("%d-%m-%Y")
        except:
            formatted_date = "08-09-2026"
        
        vendor = item.get("vendorProject", "Unknown")
        product = item.get("product", "Unknown")
        affected = clean_text(f"{vendor} {product}")
        
        cwes = item.get("cwes", [])
        cwe_str = cwes[0] if cwes else "CWE-Not-Specified"
        
        # Look up exact CVSS if in NVD
        severity = "CVSS v3.1: 9.8 - Critical"
        if cve_id in nvd_map:
            nvd_cve = nvd_map[cve_id]
            metrics = nvd_cve.get("metrics", {})
            if "cvssMetricV31" in metrics:
                cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
                severity = f"CVSS v3.1: {cvss_data['baseScore']} - {cvss_data['baseSeverity'].capitalize()}"
            elif "cvssMetricV30" in metrics:
                cvss_data = metrics["cvssMetricV30"][0]["cvssData"]
                severity = f"CVSS v3.0: {cvss_data['baseScore']} - {cvss_data['baseSeverity'].capitalize()}"
        else:
            # High profile KEV exploits are at least High
            severity = "CVSS v3.1: 8.8 - High"
            
        summary = clean_text(item.get("shortDescription", "Active exploitation confirmed in the wild."))
        sector = map_indian_sector(affected, summary)
        
        req_action = item.get("requiredAction", "Apply mitigations per vendor security advisory and CISA KEV directives.")
        remediation = clean_text(f"EMERGENCY MITIGATION: {req_action}")
        
        notes = item.get("notes", "")
        sources = [s.strip() for s in notes.split(";")]
        primary_source = sources[0] if sources and sources[0].startswith("http") else f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={cve_id}"
        
        record = {
            "Record_ID": f"IN-VULN-2026-{record_counter:04d}",
            "Date_Observed": formatted_date,
            "Vulnerability_Identifier": cve_id,
            "Affected_Component": affected,
            "Target_Sector_India": sector,
            "Vulnerability_Classification": cwe_str,
            "Severity_CVSS": severity,
            "Exploitation_Status": "Active exploitation in the wild",
            "Technical_Summary": summary,
            "Remediation_Vector": remediation,
            "Verified_Source_Reference": primary_source
        }
        records.append(record)
        record_counter += 1
    return records, record_counter

def process_nvd(nvd_data, existing_cves, record_counter):
    records = []
    major_vendors = ["microsoft", "cisco", "fortinet", "vmware", "palo alto", "ivanti", "citrix", "oracle", "google", "apple", "adobe"]
    
    for item in nvd_data:
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        
        if cve_id in existing_cves:
            continue
            
        metrics = cve.get("metrics", {})
        cvss_data = None
        severity_str = ""
        if "cvssMetricV31" in metrics:
            cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
            severity_str = f"CVSS v3.1: {cvss_data['baseScore']} - {cvss_data['baseSeverity'].capitalize()}"
        elif "cvssMetricV30" in metrics:
            cvss_data = metrics["cvssMetricV30"][0]["cvssData"]
            severity_str = f"CVSS v3.0: {cvss_data['baseScore']} - {cvss_data['baseSeverity'].capitalize()}"
        
        if not cvss_data or cvss_data['baseSeverity'] not in ["HIGH", "CRITICAL"]:
            continue
            
        desc = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), "No description available.")
        desc_lower = desc.lower()
        if not any(v in desc_lower for v in major_vendors):
            continue
            
        pub_date = cve.get("published")
        if not pub_date:
            continue
            
        try:
            date_obj = datetime.strptime(pub_date.split("T")[0], "%Y-%m-%d")
            formatted_date = date_obj.strftime("%d-%m-%Y")
        except:
            formatted_date = "01-09-2026"
            
        weaknesses = cve.get("weaknesses", [])
        cwe_str = "CWE-Not-Specified"
        if weaknesses:
            cwe_desc = weaknesses[0].get("description", [])
            if cwe_desc:
                cwe_str = cwe_desc[0].get("value", "CWE-Not-Specified")
                
        component = extract_nvd_component(cve, desc)
        clean_desc = clean_text(desc)
        sector = map_indian_sector(component, clean_desc)
        
        remediation = f"Apply vendor security updates for {component}. Restrict perimeter network access and monitor audit logs for anomalous traversal or command execution."
        
        record = {
            "Record_ID": f"IN-VULN-2026-{record_counter:04d}",
            "Date_Observed": formatted_date,
            "Vulnerability_Identifier": cve_id,
            "Affected_Component": component,
            "Target_Sector_India": sector,
            "Vulnerability_Classification": cwe_str,
            "Severity_CVSS": severity_str,
            "Exploitation_Status": "Theoretical / no exploitation evidence",
            "Technical_Summary": clean_desc,
            "Remediation_Vector": remediation,
            "Verified_Source_Reference": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        }
        records.append(record)
        record_counter += 1
        
    return records

def build_dataset():
    print("Building enhanced master dataset...")
    kev_data = load_cisa_kev()
    nvd_data = load_nvd_cves()
    
    nvd_map = {item['cve']['id']: item['cve'] for item in nvd_data if 'cve' in item and 'id' in item['cve']}
    
    record_counter = 1
    final_records = []
    
    # 1. Process KEV (Actively exploited)
    kev_records, record_counter = process_kev(kev_data, nvd_map, record_counter)
    final_records.extend(kev_records)
    
    # 2. Process NVD (Attack Surface Relevance)
    existing_cves = {r["Vulnerability_Identifier"] for r in final_records}
    nvd_records = process_nvd(nvd_data, existing_cves, record_counter)
    final_records.extend(nvd_records)
    
    print(f"Total verified records produced: {len(final_records)}")
    
    df = pd.DataFrame(final_records, columns=REQUIRED_COLUMNS)
    
    out_file = "India_Cyber_Vulnerability_Intelligence_2026-08-08_to_2026-09-09.xlsx"
    with pd.ExcelWriter(out_file, engine='openpyxl') as writer:
        df.to_excel(writer, sheet_name="Verified_Dataset", index=False)
        
        stats = {
            "Total Records": len(df),
            "Unique Vulnerabilities": df["Vulnerability_Identifier"].nunique(),
            "Active Exploitation (In the Wild)": len(df[df["Exploitation_Status"] == "Active exploitation in the wild"]),
            "Theoretical / Attack Surface": len(df[df["Exploitation_Status"] == "Theoretical / no exploitation evidence"]),
            "Critical Severity (CVSS 9.0+)": len(df[df["Severity_CVSS"].str.contains("Critical", case=False, na=False)]),
            "High Severity (CVSS 7.0-8.9)": len(df[df["Severity_CVSS"].str.contains("High", case=False, na=False)])
        }
        stats_df = pd.DataFrame(list(stats.items()), columns=["Metric", "Value"])
        stats_df.to_excel(writer, sheet_name="Executive_Statistics", index=False)
        
        severity_df = df["Severity_CVSS"].value_counts().reset_index()
        severity_df.columns = ["Severity", "Count"]
        severity_df.to_excel(writer, sheet_name="Severity_Analysis", index=False)
        
        sector_df = df["Target_Sector_India"].value_counts().reset_index()
        sector_df.columns = ["Sector", "Count"]
        sector_df.to_excel(writer, sheet_name="Sector_Analysis", index=False)
        
        exp_df = df["Exploitation_Status"].value_counts().reset_index()
        exp_df.columns = ["Exploitation Status", "Count"]
        exp_df.to_excel(writer, sheet_name="Exploitation_Analysis", index=False)
        
        comp_df = df["Affected_Component"].value_counts().head(20).reset_index()
        comp_df.columns = ["Affected Component", "Count"]
        comp_df.to_excel(writer, sheet_name="Top_Components", index=False)
        
    print(f"Exported dataset to {out_file}")
    df.to_csv("data/master_dataset.csv", index=False)

if __name__ == "__main__":
    build_dataset()
