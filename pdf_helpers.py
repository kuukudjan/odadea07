"""
pdf_helpers.py — generate PDF reports using reportlab.
"""

import io
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import (SimpleDocTemplate, Table, TableStyle,
                                Paragraph, Spacer, PageBreak)


BLUE = colors.HexColor('#1a3fbf')
RED  = colors.HexColor('#ed1c24')
GREY = colors.HexColor('#6c757d')
LIGHT = colors.HexColor('#f6f8ff')


def _style_sheet():
    ss = getSampleStyleSheet()
    ss.add(ParagraphStyle(
        name='Odadea07Title',
        fontName='Helvetica-Bold',
        fontSize=20,
        textColor=BLUE,
        spaceAfter=6,
    ))
    ss.add(ParagraphStyle(
        name='Odadea07Subtitle',
        fontName='Helvetica',
        fontSize=11,
        textColor=GREY,
        spaceAfter=16,
    ))
    ss.add(ParagraphStyle(
        name='Odadea07Section',
        fontName='Helvetica-Bold',
        fontSize=13,
        textColor=BLUE,
        spaceBefore=12,
        spaceAfter=6,
    ))
    return ss


def build_table(rows, cols):
    """Build a reportlab Table from a list of dicts and column list."""
    if not rows:
        data = [['No data']]
    else:
        header = [c.replace('_', ' ').title() for c in cols]
        data = [header] + [[str(r.get(c, '')) for c in cols] for r in rows]

    t = Table(data, repeatRows=1)
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), BLUE),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 9),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('FONTSIZE', (0, 1), (-1, -1), 8),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, LIGHT]),
        ('GRID', (0, 0), (-1, -1), 0.25, colors.HexColor('#e3e7ee')),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
    ]))
    return t


def build_pdf(title, subtitle, sections):
    """
    sections: list of (section_title, rows, cols)
    Returns bytes of a PDF.
    """
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=1.5*cm, rightMargin=1.5*cm,
        topMargin=1.5*cm, bottomMargin=1.5*cm,
    )
    ss = _style_sheet()
    story = [
        Paragraph('ODADEAƐ07', ss['Odadea07Title']),
        Paragraph(title, ss['Heading1']),
        Paragraph(subtitle, ss['Odadea07Subtitle']),
        Paragraph(f'Generated: {datetime.now().strftime("%Y-%m-%d %H:%M")}',
                  ss['Odadea07Subtitle']),
    ]

    for sec_title, rows, cols in sections:
        story.append(Paragraph(sec_title, ss['Odadea07Section']))
        story.append(build_table(rows, cols))
        story.append(Spacer(1, 8))

    doc.build(story)
    buf.seek(0)
    return buf.getvalue()