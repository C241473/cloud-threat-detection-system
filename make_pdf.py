import sys
import os

pdf_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Cloud_Security_Monitoring_System_Guide.pdf")
md_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Cloud_Security_Monitoring_System_Guide.md")

with open(md_path, "r", encoding="utf-8") as f:
    text_content = f.read()

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Preformatted
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors

    doc = SimpleDocTemplate(pdf_path, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
    styles = getSampleStyleSheet()
    story = []

    title_style = ParagraphStyle('TitleStyle', parent=styles['Heading1'], fontSize=18, leading=22, textColor=colors.HexColor("#06b6d4"))
    h2_style = ParagraphStyle('H2Style', parent=styles['Heading2'], fontSize=14, leading=18, textColor=colors.HexColor("#1e293b"))
    body_style = ParagraphStyle('BodyStyle', parent=styles['BodyText'], fontSize=10, leading=14, textColor=colors.HexColor("#334155"))
    code_style = ParagraphStyle('CodeStyle', parent=styles['Code'], fontSize=8, leading=11, backColor=colors.HexColor("#f1f5f9"), borderColor=colors.HexColor("#cbd5e1"), borderWidth=1, borderPadding=6)

    lines = text_content.split('\n')
    for line in lines:
        if line.startswith("# "):
            story.append(Paragraph(line[2:], title_style))
            story.append(Spacer(1, 10))
        elif line.startswith("## "):
            story.append(Paragraph(line[3:], h2_style))
            story.append(Spacer(1, 8))
        elif line.startswith("### "):
            story.append(Paragraph(line[4:], h2_style))
            story.append(Spacer(1, 6))
        elif line.strip():
            safe_text = line.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            story.append(Paragraph(safe_text, body_style))
            story.append(Spacer(1, 4))

    doc.build(story)
    print("PDF generated successfully via ReportLab:", pdf_path)

except Exception as e:
    print("ReportLab fallback error:", e)
