import os
import pandas as pd
from fpdf import FPDF
from fpdf.enums import XPos, YPos

df = pd.read_excel('India_Cyber_Vulnerability_Intelligence_2026-08-08_to_2026-09-09.xlsx', sheet_name='Verified_Dataset')

class TestPDF(FPDF):
    def header(self):
        if self.page_no() > 1:
            self.set_font('ArialCustom', 'B', 8)
            self.set_text_color(71, 85, 105)
            self.cell(100, 6, "INDIA CYBER VULNERABILITY & EXPLOIT INTELLIGENCE REPORT", new_x=XPos.RIGHT, new_y=YPos.TOP)
            self.cell(0, 6, f"08 AUG - 09 SEP 2026 | Page {self.page_no()}", align="R", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            self.set_draw_color(203, 213, 225)
            self.line(10, 16, 200, 16)
            self.ln(3)

    def footer(self):
        self.set_y(-12)
        self.set_font('ArialCustom', 'I', 7.5)
        self.set_text_color(148, 163, 184)
        self.cell(0, 6, "CONFIDENTIAL // CYBER THREAT INTELLIGENCE AUDIT // ALL 1,273 VERIFIED RECORDS", align="C")

pdf = TestPDF(orientation='P', unit='mm', format='A4')
pdf.set_margins(12, 12, 12)
pdf.set_auto_page_break(auto=True, margin=15)

pdf.add_font('ArialCustom', '', 'C:/Windows/Fonts/arial.ttf')
pdf.add_font('ArialCustom', 'B', 'C:/Windows/Fonts/arialbd.ttf')
pdf.add_font('ArialCustom', 'I', 'C:/Windows/Fonts/ariali.ttf')

pdf.add_page()
pdf.set_font('ArialCustom', 'B', 14)
pdf.set_text_color(15, 23, 42)
pdf.cell(0, 8, "SECTION 1: ACTIVELY EXPLOITED ATTACK PROFILES", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
pdf.ln(2)

active_df = df[df['Exploitation_Status'] == 'Active exploitation in the wild'].head(3)

for idx, row in active_df.iterrows():
    # Card container
    start_y = pdf.get_y()
    if start_y > 230:
        pdf.add_page()
        start_y = pdf.get_y()

    # Header bar
    pdf.set_fill_color(241, 245, 249)
    pdf.set_draw_color(203, 213, 225)
    
    # We can draw card box later or stream it
    pdf.set_font('ArialCustom', 'B', 9)
    pdf.set_text_color(185, 28, 28) # Red for active
    pdf.cell(35, 6, f"{row['Record_ID']}", fill=True, new_x=XPos.RIGHT, new_y=YPos.TOP)
    pdf.set_text_color(15, 23, 42)
    pdf.cell(45, 6, f"{row['Vulnerability_Identifier']}", fill=True, new_x=XPos.RIGHT, new_y=YPos.TOP)
    pdf.set_font('ArialCustom', 'B', 8.5)
    pdf.cell(45, 6, f"{row['Severity_CVSS']}", fill=True, new_x=XPos.RIGHT, new_y=YPos.TOP)
    pdf.set_font('ArialCustom', 'B', 8)
    pdf.set_text_color(220, 38, 38)
    pdf.cell(0, 6, "[ACTIVE IN THE WILD]", fill=True, align="R", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    # Sub-header
    pdf.set_font('ArialCustom', 'B', 8)
    pdf.set_text_color(71, 85, 105)
    pdf.cell(0, 5, f"Component: {row['Affected_Component']}  |  Sector: {row['Target_Sector_India']}  |  Weakness: {row['Vulnerability_Classification']}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    # Description
    pdf.set_x(12)
    pdf.set_font('ArialCustom', '', 8)
    pdf.set_text_color(30, 41, 59)
    pdf.multi_cell(w=pdf.epw, h=4.2, text=f"Attack Mechanics: {row['Technical_Summary']}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    # Mitigation
    pdf.set_x(12)
    pdf.set_font('ArialCustom', 'I', 7.5)
    pdf.set_text_color(100, 116, 139)
    pdf.multi_cell(w=pdf.epw, h=3.8, text=f"Remediation: {row['Remediation_Vector']}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_x(12)
    pdf.multi_cell(w=pdf.epw, h=3.8, text=f"Verified Reference: {row['Verified_Source_Reference']}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf.set_draw_color(226, 232, 240)
    pdf.line(12, pdf.get_y() + 2, 198, pdf.get_y() + 2)
    pdf.ln(4)

pdf.output('scratch/test_cards.pdf')
print("Successfully generated test_cards.pdf!")
