"""PDF Report Generator for CyberShield"""
import os
from datetime import datetime

def generate_pdf_report(scan_result, output_dir=None):
    """Generate a professional PDF security report."""
    if output_dir is None:
        output_dir = os.path.join(os.path.dirname(__file__), 'reports')
    os.makedirs(output_dir, exist_ok=True)
    
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.lib import colors
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
        from reportlab.lib.enums import TA_LEFT, TA_CENTER
        
        filename = f"cybershield_report_{scan_result['hostname']}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf"
        filepath = os.path.join(output_dir, filename)
        
        doc = SimpleDocTemplate(filepath, pagesize=A4,
            leftMargin=2*cm, rightMargin=2*cm, topMargin=2*cm, bottomMargin=2*cm)
        
        BLACK = colors.HexColor('#0a0a0f')
        BLUE = colors.HexColor('#0ea5e9')
        DARKBLUE = colors.HexColor('#0369a1')
        GREY = colors.HexColor('#374151')
        LIGHTGREY = colors.HexColor('#f3f4f6')
        RED = colors.HexColor('#ef4444')
        ORANGE = colors.HexColor('#f97316')
        YELLOW = colors.HexColor('#f59e0b')
        GREEN = colors.HexColor('#22c55e')
        WHITE = colors.white
        
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle('Title', fontName='Helvetica-Bold', fontSize=24, textColor=WHITE, spaceAfter=4)
        h1_style = ParagraphStyle('H1', fontName='Helvetica-Bold', fontSize=14, textColor=BLUE, spaceAfter=8, spaceBefore=16)
        body_style = ParagraphStyle('Body', fontName='Helvetica', fontSize=10, textColor=GREY, spaceAfter=6, leading=16)
        small_style = ParagraphStyle('Small', fontName='Helvetica', fontSize=8, textColor=GREY)
        
        story = []
        
        # Header Banner
        header_data = [[
            Paragraph('<font color="white"><b>CYBERSHIELD</b></font>', ParagraphStyle('', fontName='Helvetica-Bold', fontSize=20, textColor=WHITE)),
            Paragraph(f'<font color="#0ea5e9">Security Audit Report</font><br/><font color="#9ca3af" size="8">{scan_result["scanned_at"]}</font>',
                ParagraphStyle('', fontName='Helvetica', fontSize=12, textColor=BLUE))
        ]]
        header_table = Table(header_data, colWidths=[9*cm, 8*cm])
        header_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), BLACK),
            ('PADDING', (0,0), (-1,-1), 12),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ]))
        story.append(header_table)
        story.append(Spacer(1, 0.5*cm))
        
        # Score section
        score = scan_result['score']
        score_color = RED if score < 40 else (ORANGE if score < 60 else (YELLOW if score < 80 else GREEN))
        score_data = [[
            Paragraph(f'<font color="{score_color.hexval()}" size="36"><b>{score}</b></font><br/><font color="#9ca3af" size="9">SECURITY SCORE</font>',
                ParagraphStyle('', fontName='Helvetica-Bold', fontSize=36, alignment=TA_CENTER)),
            Paragraph(f'<font color="#111827" size="11"><b>Risk Level: {scan_result["risk_level"]}</b></font><br/><br/>'
                f'<font color="#4b5563" size="9">{scan_result["ai_summary"]}</font>',
                ParagraphStyle('', fontName='Helvetica', fontSize=9, leading=14)),
        ]]
        score_table = Table(score_data, colWidths=[4*cm, 13*cm])
        score_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (0,0), LIGHTGREY),
            ('BACKGROUND', (1,0), (1,0), colors.HexColor('#f9fafb')),
            ('PADDING', (0,0), (-1,-1), 14),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#e5e7eb')),
        ]))
        story.append(score_table)
        story.append(Spacer(1, 0.5*cm))
        
        # Stats row
        stats = scan_result['stats']
        stat_items = [
            (str(stats['critical']), 'CRITICAL', '#ef4444'),
            (str(stats['warnings']), 'WARNINGS', '#f59e0b'),
            (str(stats['passed']), 'PASSED', '#22c55e'),
            (str(stats['total']), 'TOTAL CHECKS', '#0ea5e9'),
        ]
        stat_data = [[Paragraph(f'<font color="{c}" size="20"><b>{v}</b></font><br/><font color="#6b7280" size="8">{l}</font>',
            ParagraphStyle('', fontName='Helvetica-Bold', alignment=TA_CENTER)) for v, l, c in stat_items]]
        stat_table = Table(stat_data, colWidths=[4.25*cm]*4)
        stat_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), LIGHTGREY),
            ('PADDING', (0,0), (-1,-1), 10),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#e5e7eb')),
            ('LINEBEFORE', (1,0), (-1,-1), 1, colors.HexColor('#e5e7eb')),
        ]))
        story.append(stat_table)
        story.append(Spacer(1, 0.5*cm))
        
        # Findings
        story.append(Paragraph('Detailed Security Findings', h1_style))
        
        sev_colors = {'critical': '#ef4444', 'high': '#f97316', 'medium': '#f59e0b', 'low': '#3b82f6', 'none': '#22c55e', 'info': '#6b7280'}
        status_labels = {'pass': '✓ PASS', 'fail': '✗ FAIL', 'warning': '⚠ WARN', 'error': '? ERROR', 'info': 'ℹ INFO'}
        
        for f in scan_result['findings']:
            sev = f.get('severity', 'info')
            color_hex = sev_colors.get(sev, '#6b7280')
            status_label = status_labels.get(f['status'], f['status'].upper())
            
            row_data = [[
                Paragraph(f'<font color="{color_hex}"><b>{status_label}</b></font>', ParagraphStyle('', fontName='Helvetica-Bold', fontSize=9, alignment=TA_CENTER)),
                Paragraph(f'<b>{f["check"]}</b>', ParagraphStyle('', fontName='Helvetica-Bold', fontSize=9)),
                Paragraph(f['details'], ParagraphStyle('', fontName='Helvetica', fontSize=8, textColor=colors.HexColor('#4b5563'), leading=12)),
            ]]
            row_table = Table(row_data, colWidths=[2.5*cm, 5.5*cm, 9*cm])
            row_color = colors.HexColor('#fff7f7') if f['status'] == 'fail' else (colors.HexColor('#fffbf0') if f['status'] == 'warning' else colors.HexColor('#f0fff4'))
            row_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,-1), row_color),
                ('PADDING', (0,0), (-1,-1), 8),
                ('VALIGN', (0,0), (-1,-1), 'TOP'),
                ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#e5e7eb')),
            ]))
            story.append(row_table)
            
            if f.get('fix'):
                fix_data = [[
                    Paragraph('HOW TO FIX:', ParagraphStyle('', fontName='Helvetica-Bold', fontSize=7, textColor=BLUE)),
                    Paragraph(f['fix'], ParagraphStyle('', fontName='Helvetica', fontSize=8, textColor=GREY, leading=12)),
                ]]
                fix_table = Table(fix_data, colWidths=[2.5*cm, 14.5*cm])
                fix_table.setStyle(TableStyle([
                    ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#eff6ff')),
                    ('PADDING', (0,0), (-1,-1), 6),
                    ('VALIGN', (0,0), (-1,-1), 'TOP'),
                    ('BOTTOMPADDING', (0,0), (-1,-1), 8),
                ]))
                story.append(fix_table)
            story.append(Spacer(1, 0.2*cm))
        
        # Footer
        story.append(Spacer(1, 0.5*cm))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#e5e7eb')))
        story.append(Spacer(1, 0.2*cm))
        story.append(Paragraph(f'Generated by CyberShield AI Security Platform | {scan_result["scanned_at"]} | For: {scan_result["url"]}',
            ParagraphStyle('', fontName='Helvetica', fontSize=7, textColor=colors.HexColor('#9ca3af'), alignment=TA_CENTER)))
        
        doc.build(story)
        return filename
    except ImportError:
        return None
