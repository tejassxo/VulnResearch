import time
import os
import pandas as pd
from fpdf import FPDF

df = pd.read_excel('India_Cyber_Vulnerability_Intelligence_2026-08-08_to_2026-09-09.xlsx', sheet_name='Verified_Dataset')
print(f"Loaded {len(df)} records")

t0 = time.time()

class TestPDF(FPDF):
    def header(self):
        if self.page_no() > 1:
            self.set_font('ArialCustom', 'B', 8)
            self.set_text_color(100, 116, 139)
            self.cell(0, 8, "INDIA CYBER VULNERABILITY & EXPLOIT INTELLIGENCE REPORT | 08 AUG - 09 SEP 2026", 0, 0, "L")
            self.cell(0, 8, f"Page {self.page_no()}", 0, 1, "R")
            self.line(10, 18, 200, 18)
            self.ln(3)

    def footer(self):
        self.set_y(-12)
        self.set_font('ArialCustom', 'I', 7)
        self.set_text_color(148, 163, 184)
        self.cell(0, 8, "RESTRICTED / CTI AUDIT - NATIONAL ATTACK SURFACE RELEVANCE (INDIA)", 0, 0, "C")

pdf = TestPDF(orientation='P', unit='mm', format='A4')
pdf.set_auto_page_break(auto=True, margin=15)

# Add fonts
arial_path = 'C:/Windows/Fonts/arial.ttf'
arial_b_path = 'C:/Windows/Fonts/arialbd.ttf'
arial_i_path = 'C:/Windows/Fonts/ariali.ttf'

pdf.add_font('ArialCustom', '', arial_path)
pdf.add_font('ArialCustom', 'B', arial_b_path)
pdf.add_font('ArialCustom', 'I', arial_i_path)

pdf.add_page()
pdf.set_font('ArialCustom', 'B', 16)
pdf.cell(0, 10, "Test Run - 1,273 Records", ln=True)

for idx, row in df.head(50).iterrows():
    pdf.set_font('ArialCustom', 'B', 9)
    pdf.cell(0, 6, f"[{row['Record_ID']}] {row['Vulnerability_Identifier']} - {row['Affected_Component']}", ln=True)
    pdf.set_font('ArialCustom', '', 8)
    summary = str(row['Technical_Summary']).encode('ascii', 'replace').decode('ascii')
    pdf.multi_cell(0, 4, f"Summary: {summary}")
    pdf.ln(2)

pdf.output('scratch/test_partial.pdf')
t1 = time.time()
print(f"50 records generated in {t1 - t0:.2f} seconds.")
