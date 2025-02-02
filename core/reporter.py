from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet

class ReportGenerator:
    """Generate professional PDF reports"""
    
    def __init__(self):
        self.styles = getSampleStyleSheet()
        
    def create_pdf(self, findings: list, output_file: str = "threat_report.pdf") -> None:
        """Generate PDF from analysis results"""
        doc = SimpleDocTemplate(output_file, pagesize=letter)
        story = []
        
        # Title
        story.append(Paragraph("ThreatForge Analysis Report", self.styles['Title']))
        story.append(Spacer(1, 12))
        
        # Findings
        for finding in findings:
            content = f"""
            <b>File Hash:</b> {finding['md5']}<br/>
            <b>Malware Type:</b> {finding.get('type', 'Unknown')}<br/>
            <b>MITRE Technique:</b> {finding.get('technique', 'T1190')}
            """
            story.append(Paragraph(content, self.styles['BodyText']))
            story.append(Spacer(1, 12))
            
        doc.build(story)
        print(f"✅ Report saved as {output_file}")

if __name__ == "__main__":
    sample_findings = [{"md5": "44d88612fea8a8f36de82e1278abb02f", "type": "EICAR Test File"}]
    reporter = ReportGenerator()
    reporter.create_pdf(sample_findings)
