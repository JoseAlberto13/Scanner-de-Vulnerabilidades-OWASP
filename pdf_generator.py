"""
pdf_generator.py - Generador de reportes PDF
"""
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from datetime import datetime
import os

from config import Config

class PDFReportGenerator:
    """Generador de reportes PDF para vulnerabilidades"""

    OWASP_CATEGORY_MAP = {
        'Security Headers': "A05:2021 – Security Misconfiguration",
        'SSL/TLS': "A02:2021 – Cryptographic Failures",
        'Transport Security': "A02:2021 – Cryptographic Failures",
        'Cookies': "A05:2021 – Security Misconfiguration",
        'HTTP Methods': "A05:2021 – Security Misconfiguration",
        'Information Disclosure': "A05:2021 – Security Misconfiguration",
        'Network Services': "A05:2021 – Security Misconfiguration",
        'Nmap': "A05:2021 – Security Misconfiguration",
        'Conexión': "A09:2021 – Security Logging and Monitoring Failures",
        'Escaneo': "A09:2021 – Security Logging and Monitoring Failures"
    }
    
    SEVERITY_ORDER = ['HIGH', 'MEDIUM', 'LOW', 'INFO', 'ERROR']
    
    def __init__(self, reports_dir):
        self.reports_dir = reports_dir
        
    def generate(self, scan_results, filename=None):
        """
        Genera un reporte PDF con los resultados del escaneo
        
        Args:
            scan_results (dict): Resultados del escaneo
            filename (str, optional): Nombre del archivo. Si es None, se genera automáticamente
            
        Returns:
            str: Ruta del archivo PDF generado
        """
        if filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"reporte_{timestamp}.pdf"
            
        pdf_path = os.path.join(self.reports_dir, filename)
        
        # Crear documento
        doc = SimpleDocTemplate(
            pdf_path,
            pagesize=letter,
            rightMargin=72,
            leftMargin=72,
            topMargin=42,
            bottomMargin=18
        )
        
        # Contenedor de elementos
        story = []
        styles = getSampleStyleSheet()
        
        # Estilos personalizados
        self._create_custom_styles(styles)
        
        # Construir el reporte
        self._add_header(story, styles)
        self._add_scan_info(story, styles, scan_results)
        self._add_summary(story, styles, scan_results)
        self._add_owasp_impact(story, styles, scan_results)

        if scan_results.get('findings'):
            story.append(PageBreak())
        
        self._add_findings(story, styles, scan_results)
        self._add_footer(story, styles)
        
        # Generar PDF
        doc.build(story)
        
        print(f"✓ Reporte generado: {pdf_path}")
        return pdf_path
    
    def _create_custom_styles(self, styles):
        """Crea estilos personalizados para el PDF"""
        styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#0F4C75'),
            spaceAfter=30,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        ))
        
        styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#3282B8'),
            spaceAfter=12,
            spaceBefore=12,
            fontName='Helvetica-Bold'
        ))
        
        styles.add(ParagraphStyle(
            name='FindingTitle',
            parent=styles['Heading3'],
            fontSize=12,
            textColor=colors.HexColor('#0F4C75'),
            spaceAfter=6,
            fontName='Helvetica-Bold'
        ))
    
    def _add_header(self, story, styles):
        """Agrega el encabezado del reporte"""
        story.append(Paragraph("🛡️ REPORTE DE VULNERABILIDADES", styles['CustomTitle']))
        story.append(Paragraph("Análisis de Seguridad Web - OWASP", styles['CustomTitle']))
        story.append(Spacer(1, 0.18 * inch))
        
        # Línea separadora
        story.append(Spacer(1, 0.05 * inch))
    
    def _add_scan_info(self, story, styles, scan_results):
        """Agrega información del escaneo"""
        story.append(Paragraph("Información del Escaneo", styles['SectionHeader']))
        
        info_data = [
            ['URL Analizada:', scan_results['url']],
            ['Fecha de Análisis:', scan_results['timestamp']],
            ['Total de Hallazgos:', str(len(scan_results['findings']))]
        ]
        
        info_table = Table(info_data, colWidths=[2*inch, 4.5*inch])
        info_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#BBE1FA')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#0F4C75')),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#D3E6F5'))
        ]))
        
        story.append(info_table)
        story.append(Spacer(1, 0.18 * inch))
    
    def _add_summary(self, story, styles, scan_results):
        """Agrega resumen de vulnerabilidades"""
        story.append(Paragraph("Resumen de Vulnerabilidades", styles['SectionHeader']))
        
        summary = scan_results.get('summary', {})
        
        summary_data = [
            ['Severidad', 'Cantidad', 'Color'],
            ['Alta', str(summary.get('high', 0)), '●'],
            ['Media', str(summary.get('medium', 0)), '●'],
            ['Baja', str(summary.get('low', 0)), '●'],
            ['Información', str(summary.get('info', 0)), '●']
        ]
        
        summary_table = Table(summary_data, colWidths=[2*inch, 2*inch, 1*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0F4C75')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#E8F5FF')),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#D3E6F5')),
            ('TEXTCOLOR', (2, 1), (2, 1), colors.red),
            ('TEXTCOLOR', (2, 2), (2, 2), colors.orange),
            ('TEXTCOLOR', (2, 3), (2, 3), colors.HexColor('#48BB78')),
            ('TEXTCOLOR', (2, 4), (2, 4), colors.HexColor('#3282B8')),
            ('FONTSIZE', (2, 1), (2, -1), 14)
        ]))
        
        story.append(summary_table)
        story.append(Spacer(1, 0.22 * inch))

    def _add_owasp_impact(self, story, styles, scan_results):
        """Lista OWASP Top 10 impactadas en el dominio"""
        affected = self._get_affected_owasp(scan_results)
        
        story.append(Paragraph("OWASP Top 10 Impactadas", styles['SectionHeader']))
        story.append(Spacer(1, 0.08 * inch))
        
        if not affected:
            story.append(Paragraph("No se detectaron vulnerabilidades alineadas al OWASP Top 10.", styles['Normal']))
            story.append(Spacer(1, 0.2 * inch))
            return
        
        data = [['Vulnerabilidad', 'Severidad', 'Descripción']]
        for entry in affected:
            data.append([
                entry['title'],
                Paragraph(f"<b>{entry['severity']}</b>", styles['Normal']),
                Paragraph(entry['description'], styles['Normal'])
            ])
        
        table = Table(data, colWidths=[2.5*inch, 1*inch, 3*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0F4C75')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#D3E6F5')),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#EAF4FF')),
            ('FONTSIZE', (0, 1), (-1, -1), 9),
        ]))
        
        story.append(table)
        story.append(Spacer(1, 0.2 * inch))
    
    def _add_findings(self, story, styles, scan_results):
        """Agrega los hallazgos detallados"""
        story.append(Paragraph("Hallazgos Detallados", styles['SectionHeader']))
        story.append(Spacer(1, 0.12 * inch))
        
        if not scan_results['findings']:
            story.append(Paragraph("No se encontraron vulnerabilidades.", styles['Normal']))
            return
        
        severity_colors = {
            'HIGH': colors.red,
            'MEDIUM': colors.orange,
            'LOW': colors.green,
            'INFO': colors.HexColor('#3282B8'),
            'ERROR': colors.red
        }

        max_per_page = 5
        per_page_count = 0
        total_findings = len(scan_results['findings'])
        
        for index, finding in enumerate(scan_results['findings'], 1):
            # Encabezado del hallazgo
            finding_title = f"{index}. {finding['issue']}"
            story.append(Paragraph(finding_title, styles['FindingTitle']))
            
            # Tabla de detalles
            severity_color = severity_colors.get(finding['severity'], colors.grey)
            
            details_data = [
                ['Severidad:', Paragraph(f"<font color='{severity_color}'><b>{finding['severity']}</b></font>", styles['Normal'])],
                ['Categoría:', finding['category']],
                ['Descripción:', Paragraph(finding['description'], styles['Normal'])],
                ['Recomendación:', Paragraph(finding['recommendation'], styles['Normal'])]
            ]
            
            details_table = Table(details_data, colWidths=[1.5*inch, 5*inch])
            details_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#BBE1FA')),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#0F4C75')),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#D3E6F5'))
            ]))
            
            story.append(details_table)
            story.append(Spacer(1, 0.12 * inch))
            
            per_page_count += 1
            remaining = total_findings - index
            
            if per_page_count == max_per_page and remaining > 0:
                story.append(Paragraph("Hallazgos Detallados", styles['SectionHeader']))
                story.append(Spacer(1, 0.12 * inch))
                per_page_count = 0

    def _get_affected_owasp(self, scan_results):
        """Devuelve lista única de vulnerabilidades OWASP impactadas"""
        impacts = {}
        severity_rank = {name: idx for idx, name in enumerate(self.SEVERITY_ORDER)}

        for finding in scan_results.get('findings', []):
            category = finding.get('category')
            mapped_title = self.OWASP_CATEGORY_MAP.get(category)

            # Permitir que los hallazgos indiquen explícitamente una entrada OWASP
            mapped_title = finding.get('owasp') or mapped_title

            if not mapped_title:
                continue

            owasp_entry = next((item for item in Config.OWASP_TOP_10 if item['title'] == mapped_title), None)
            description = owasp_entry['description'] if owasp_entry else 'Riesgo documentado en OWASP Top 10.'
            severity = finding.get('severity', 'INFO')

            if mapped_title not in impacts:
                impacts[mapped_title] = {
                    'title': mapped_title,
                    'description': description,
                    'severity': severity
                }
            else:
                current_rank = severity_rank.get(impacts[mapped_title]['severity'], len(self.SEVERITY_ORDER))
                new_rank = severity_rank.get(severity, len(self.SEVERITY_ORDER))
                if new_rank < current_rank:
                    impacts[mapped_title]['severity'] = severity

        return list(impacts.values())
    
    def _add_footer(self, story, styles):
        """Agrega pie de página"""
        story.append(Spacer(1, 0.5 * inch))
        footer_style = ParagraphStyle(
            'Footer',
            parent=styles['Normal'],
            fontSize=8,
            textColor=colors.grey,
            alignment=TA_CENTER
        )
        story.append(Paragraph(
            "Este reporte fue generado automáticamente por el Scanner de Vulnerabilidades OWASP",
            footer_style
        ))
        story.append(Paragraph(
            f"© {datetime.now().year} - Para uso educativo y de pruebas únicamente",
            footer_style
        ))
        story.append(Paragraph(
            f"Técnico de Nivel Superior en Analista Programador - CFT Lota Arauco",
            footer_style
        ))