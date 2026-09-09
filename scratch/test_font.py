import os
from fpdf import FPDF

pdf = FPDF()
pdf.add_page()

# Check font paths
arial_path = 'C:/Windows/Fonts/arial.ttf'
arial_b_path = 'C:/Windows/Fonts/arialbd.ttf'
arial_i_path = 'C:/Windows/Fonts/ariali.ttf'

if os.path.exists(arial_path):
    pdf.add_font('ArialCustom', '', arial_path)
    if os.path.exists(arial_b_path):
        pdf.add_font('ArialCustom', 'B', arial_b_path)
    if os.path.exists(arial_i_path):
        pdf.add_font('ArialCustom', 'I', arial_i_path)
    pdf.set_font('ArialCustom', '', 12)
    pdf.cell(0, 10, 'Testing unicode: \u2014 \u2018 \u2019 \u201c \u201d \u010d \u2022')
    pdf.output('scratch/font_test_output.pdf')
    print('Successfully generated PDF with ArialCustom and unicode!')
else:
    print('Arial font not found!')
