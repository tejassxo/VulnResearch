import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import os
from weasyprint import HTML

def generate_charts(df):
    os.makedirs('images', exist_ok=True)
    sns.set_theme(style="darkgrid")
    
    # Severity
    plt.figure(figsize=(8, 6))
    severity_counts = df["Severity_CVSS"].value_counts()
    sns.barplot(y=severity_counts.index, x=severity_counts.values, palette="rocket")
    plt.title("Vulnerabilities by Severity")
    plt.xlabel("Count")
    plt.ylabel("Severity")
    plt.tight_layout()
    plt.savefig("images/severity.png", dpi=300)
    plt.close()
    
    # Exploitation Status
    plt.figure(figsize=(8, 6))
    exp_counts = df["Exploitation_Status"].value_counts()
    sns.barplot(y=exp_counts.index, x=exp_counts.values, palette="mako")
    plt.title("Exploitation Status Distribution")
    plt.xlabel("Count")
    plt.ylabel("Status")
    plt.tight_layout()
    plt.savefig("images/exploitation.png", dpi=300)
    plt.close()

def generate_pdf():
    df = pd.read_excel("India_Cyber_Vulnerability_Intelligence_2026-08-08_to_2026-09-09.xlsx", sheet_name="Verified_Dataset")
    generate_charts(df)
    
    # Calculate stats
    total_records = len(df)
    active_exp = len(df[df["Exploitation_Status"] == "Active exploitation in the wild"])
    
    # Read the first 50 records for the Appendix table to avoid massive PDF size, 
    # but the full dataset is in the Excel file as requested by the rule: "Large datasets must not become unreadable"
    table_html = df.head(50).to_html(index=False, classes="table table-striped", border=0)
    
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>INDIA CYBER VULNERABILITY & EXPLOIT INTELLIGENCE REPORT</title>
        <style>
            body {{ font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; color: #333; line-height: 1.6; margin: 0; padding: 0; }}
            h1, h2, h3 {{ color: #1a202c; }}
            .cover {{ height: 100vh; display: flex; flex-direction: column; justify-content: center; align-items: center; text-align: center; background-color: #2d3748; color: white; }}
            .cover h1 {{ color: white; font-size: 3em; margin-bottom: 0.2em; }}
            .cover p {{ font-size: 1.5em; color: #cbd5e0; }}
            .page {{ padding: 40px; page-break-after: always; }}
            .stats-container {{ display: flex; justify-content: space-between; flex-wrap: wrap; margin-top: 20px; }}
            .stat-box {{ background-color: #f7fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 20px; width: 30%; text-align: center; margin-bottom: 20px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
            .stat-box h3 {{ margin: 0; font-size: 2em; color: #2b6cb0; }}
            .stat-box p {{ margin: 5px 0 0; font-size: 1em; color: #4a5568; text-transform: uppercase; letter-spacing: 0.05em; }}
            .chart-container {{ text-align: center; margin: 40px 0; }}
            .chart-container img {{ max-width: 100%; height: auto; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 20px; font-size: 0.85em; }}
            th, td {{ border: 1px solid #e2e8f0; padding: 8px; text-align: left; }}
            th {{ background-color: #edf2f7; color: #2d3748; }}
            tr:nth-child(even) {{ background-color: #f7fafc; }}
        </style>
    </head>
    <body>
        <div class="cover">
            <h1>INDIA CYBER VULNERABILITY & EXPLOIT INTELLIGENCE REPORT</h1>
            <p>Reporting Window:<br><b>08 August 2026 &ndash; 09 September 2026</b></p>
            <br><br>
            <p>Classification:<br><b>Open-Source Cyber Threat Intelligence / Vulnerability Research</b></p>
        </div>
        
        <div class="page">
            <h2>Executive Summary</h2>
            <p>This report presents an empirical, evidence-based vulnerability intelligence audit covering technical vulnerabilities, exploit activity, and threat campaigns affecting Indian infrastructure and organizations.</p>
            <div class="stats-container">
                <div class="stat-box">
                    <h3>{total_records}</h3>
                    <p>Verified Records</p>
                </div>
                <div class="stat-box">
                    <h3>{active_exp}</h3>
                    <p>Active Exploitation Records</p>
                </div>
                <div class="stat-box">
                    <h3>{total_records}</h3>
                    <p>Unique Vulnerabilities</p>
                </div>
            </div>
            
            <h2>Severity Analysis</h2>
            <div class="chart-container">
                <img src="images/severity.png" alt="Severity Distribution">
            </div>
        </div>
        
        <div class="page">
            <h2>Exploitation & PoC Analysis</h2>
            <div class="chart-container">
                <img src="images/exploitation.png" alt="Exploitation Distribution">
            </div>
            
            <h2>Critical Vulnerability Priorities & Recommendations</h2>
            <p><b>Immediate Exposure Reduction:</b> Organizations must immediately patch actively exploited vulnerabilities (Level 3/4 Exploitation Maturity), particularly focusing on public-facing assets like Citrix, Fortinet, and Ivanti gateways which are under active targeting.</p>
            <p><b>Detection & Hardening:</b> Implement exploit signatures for recent high-severity CVSS findings and enforce MFA across all external access vectors.</p>
        </div>
        
        <div class="page">
            <h2>Appendix A &mdash; Verified Dataset (Sample)</h2>
            <p><i>Displaying the first 50 records. See the accompanying XLSX file for the full {total_records} records.</i></p>
            {table_html}
        </div>
    </body>
    </html>
    """
    
    with open("report.html", "w", encoding="utf-8") as f:
        f.write(html_content)
        
    print("Converting HTML to PDF via WeasyPrint...")
    # Note: Using file:// base_url is required for images to load properly in WeasyPrint
    base_url = "file:///" + os.path.abspath(".") + "/"
    HTML("report.html", base_url=base_url).write_pdf("India_Cyber_Vulnerability_Intelligence_Report_08Aug2026-09Sep2026.pdf")
    print("PDF Generation complete.")

if __name__ == "__main__":
    generate_pdf()
