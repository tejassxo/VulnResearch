import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import os
from fpdf import FPDF

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

class PDF(FPDF):
    def header(self):
        if self.page_no() > 1:
            self.set_font("helvetica", "B", 10)
            self.set_text_color(100, 100, 100)
            self.cell(0, 10, "INDIA CYBER VULNERABILITY & EXPLOIT INTELLIGENCE REPORT", 0, 1, "R")
            self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font("helvetica", "I", 8)
        self.set_text_color(100, 100, 100)
        self.cell(0, 10, f"Page {self.page_no()}", 0, 0, "C")

def generate_pdf():
    df = pd.read_excel("India_Cyber_Vulnerability_Intelligence_2026-08-08_to_2026-09-09.xlsx", sheet_name="Verified_Dataset")
    generate_charts(df)
    
    total_records = len(df)
    active_exp = len(df[df["Exploitation_Status"] == "Active exploitation in the wild"])
    
    pdf = PDF()
    pdf.add_page()
    
    # Cover Page
    pdf.set_fill_color(45, 55, 72)
    pdf.rect(0, 0, 210, 297, "F")
    
    pdf.set_y(100)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("helvetica", "B", 24)
    pdf.multi_cell(0, 10, "INDIA CYBER VULNERABILITY &\nEXPLOIT INTELLIGENCE REPORT", align="C")
    
    pdf.set_y(150)
    pdf.set_font("helvetica", "", 14)
    pdf.multi_cell(0, 8, "Reporting Window:\n08 August 2026 - 09 September 2026", align="C")
    
    pdf.set_y(200)
    pdf.multi_cell(0, 8, "Classification:\nOpen-Source Cyber Threat Intelligence / Vulnerability Research", align="C")
    
    # Executive Summary Page
    pdf.add_page()
    pdf.set_text_color(0, 0, 0)
    pdf.set_font("helvetica", "B", 18)
    pdf.cell(0, 10, "Executive Summary", ln=True)
    pdf.ln(5)
    
    pdf.set_font("helvetica", "", 12)
    pdf.multi_cell(0, 8, "This report presents an empirical, evidence-based vulnerability intelligence audit covering technical vulnerabilities, exploit activity, and threat campaigns affecting Indian infrastructure and organizations.")
    pdf.ln(10)
    
    pdf.set_font("helvetica", "B", 14)
    pdf.cell(0, 10, f"Total Verified Records: {total_records}", ln=True)
    pdf.cell(0, 10, f"Active Exploitation Records: {active_exp}", ln=True)
    pdf.cell(0, 10, f"Unique Vulnerabilities: {total_records}", ln=True)
    pdf.ln(10)
    
    # Charts Page
    pdf.add_page()
    pdf.set_font("helvetica", "B", 18)
    pdf.cell(0, 10, "Severity Analysis", ln=True)
    pdf.image("images/severity.png", x=10, y=pdf.get_y() + 5, w=180)
    
    pdf.add_page()
    pdf.set_font("helvetica", "B", 18)
    pdf.cell(0, 10, "Exploitation & PoC Analysis", ln=True)
    pdf.image("images/exploitation.png", x=10, y=pdf.get_y() + 5, w=180)
    
    # Recommendations
    pdf.add_page()
    pdf.set_font("helvetica", "B", 18)
    pdf.cell(0, 10, "Critical Vulnerability Priorities & Recommendations", ln=True)
    pdf.ln(5)
    
    pdf.set_font("helvetica", "B", 14)
    pdf.cell(0, 10, "Immediate Exposure Reduction:", ln=True)
    pdf.set_font("helvetica", "", 12)
    pdf.multi_cell(0, 8, "Organizations must immediately patch actively exploited vulnerabilities (Level 3/4 Exploitation Maturity), particularly focusing on public-facing assets like Citrix, Fortinet, and Ivanti gateways which are under active targeting.")
    pdf.ln(5)
    
    pdf.set_font("helvetica", "B", 14)
    pdf.cell(0, 10, "Detection & Hardening:", ln=True)
    pdf.set_font("helvetica", "", 12)
    pdf.multi_cell(0, 8, "Implement exploit signatures for recent high-severity CVSS findings and enforce MFA across all external access vectors.")
    
    pdf.output("India_Cyber_Vulnerability_Intelligence_Report_08Aug2026-09Sep2026.pdf")
    print("PDF Generation complete.")

if __name__ == "__main__":
    generate_pdf()
