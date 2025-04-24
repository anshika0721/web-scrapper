"""
Reporter module for handling scan results and reporting
"""

import csv
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional

class Reporter:
    """Handler for scan results and reporting"""
    
    def __init__(self):
        """Initialize reporter"""
        self.severity_colors = {
            "critical": "\033[91m",  # Red
            "high": "\033[31m",      # Light Red
            "medium": "\033[93m",    # Yellow
            "low": "\033[92m",       # Green
            "info": "\033[94m",      # Blue
        }
    
    def save_results(self, results: Dict, output_file: str) -> None:
        """
        Save scan results to file
        
        Args:
            results: Scan results to save
            output_file: Output file path
        """
        try:
            if output_file.endswith('.json'):
                self._save_json(results, output_file)
            elif output_file.endswith('.csv'):
                self._save_csv(results, output_file)
            else:
                logging.error(f"Unsupported output format: {output_file}")
        except Exception as e:
            logging.error(f"Error saving results: {e}")
    
    def _save_json(self, results: Dict, output_file: str) -> None:
        """Save results in JSON format"""
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
    
    def _save_csv(self, results: Dict, output_file: str) -> None:
        """Save results in CSV format"""
        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            
            # Write header
            writer.writerow([
                'Vulnerability Type',
                'Severity',
                'URL',
                'Evidence',
                'Description'
            ])
            
            # Write vulnerabilities
            for vuln in results.get('vulnerabilities', []):
                writer.writerow([
                    vuln.get('type', ''),
                    vuln.get('severity', ''),
                    vuln.get('url', ''),
                    vuln.get('evidence', ''),
                    vuln.get('description', '')
                ])
    
    def print_results(self, results: Dict) -> None:
        """
        Print scan results to console
        
        Args:
            results: Scan results to print
        """
        print("\n=== Scan Results ===\n")
        
        # Print scan info
        print(f"Target URL: {results.get('target_url', '')}")
        print(f"Scan Time: {results.get('scan_time', '')}")
        print(f"Total Endpoints: {len(results.get('endpoints', []))}")
        print(f"Total Vulnerabilities: {len(results.get('vulnerabilities', []))}")
        
        # Print technologies
        print("\n=== Detected Technologies ===\n")
        for tech in results.get('technologies', []):
            print(f"{tech['name']} ({tech['type']}) - Confidence: {tech['confidence']}")
            print(f"Evidence: {tech['evidence']}\n")
        
        # Print vulnerabilities
        print("\n=== Vulnerabilities ===\n")
        for vuln in results.get('vulnerabilities', []):
            severity = vuln.get('severity', 'info').lower()
            color = self.severity_colors.get(severity, '')
            
            print(f"{color}[{severity.upper()}]{color} {vuln.get('type', '')}")
            print(f"URL: {vuln.get('url', '')}")
            print(f"Evidence: {vuln.get('evidence', '')}")
            print(f"Description: {vuln.get('description', '')}\n")
    
    def generate_report(self, results: Dict, template: Optional[str] = None) -> str:
        """
        Generate HTML report from scan results
        
        Args:
            results: Scan results
            template: Optional HTML template
            
        Returns:
            Generated HTML report
        """
        if template:
            # Use custom template
            with open(template, 'r') as f:
                html = f.read()
        else:
            # Use default template
            html = self._get_default_template()
        
        # Replace placeholders
        html = html.replace('{{TARGET_URL}}', results.get('target_url', ''))
        html = html.replace('{{SCAN_TIME}}', results.get('scan_time', ''))
        html = html.replace('{{TOTAL_ENDPOINTS}}', str(len(results.get('endpoints', []))))
        html = html.replace('{{TOTAL_VULNS}}', str(len(results.get('vulnerabilities', []))))
        
        # Add technologies
        tech_html = ""
        for tech in results.get('technologies', []):
            tech_html += f"""
                <div class="tech-item">
                    <h3>{tech['name']} ({tech['type']})</h3>
                    <p>Confidence: {tech['confidence']}</p>
                    <p>Evidence: {tech['evidence']}</p>
                </div>
            """
        html = html.replace('{{TECHNOLOGIES}}', tech_html)
        
        # Add vulnerabilities
        vuln_html = ""
        for vuln in results.get('vulnerabilities', []):
            vuln_html += f"""
                <div class="vuln-item {vuln.get('severity', 'info').lower()}">
                    <h3>{vuln.get('type', '')}</h3>
                    <p>URL: {vuln.get('url', '')}</p>
                    <p>Evidence: {vuln.get('evidence', '')}</p>
                    <p>Description: {vuln.get('description', '')}</p>
                </div>
            """
        html = html.replace('{{VULNERABILITIES}}', vuln_html)
        
        return html
    
    def _get_default_template(self) -> str:
        """Get default HTML report template"""
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Web Vulnerability Scan Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .header { background: #f5f5f5; padding: 20px; margin-bottom: 20px; }
                .tech-item { border: 1px solid #ddd; padding: 10px; margin: 10px 0; }
                .vuln-item { border: 1px solid #ddd; padding: 10px; margin: 10px 0; }
                .critical { border-left: 5px solid #ff0000; }
                .high { border-left: 5px solid #ff4500; }
                .medium { border-left: 5px solid #ffa500; }
                .low { border-left: 5px solid #00ff00; }
                .info { border-left: 5px solid #0000ff; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Web Vulnerability Scan Report</h1>
                <p>Target URL: {{TARGET_URL}}</p>
                <p>Scan Time: {{SCAN_TIME}}</p>
                <p>Total Endpoints: {{TOTAL_ENDPOINTS}}</p>
                <p>Total Vulnerabilities: {{TOTAL_VULNS}}</p>
            </div>
            
            <h2>Detected Technologies</h2>
            {{TECHNOLOGIES}}
            
            <h2>Vulnerabilities</h2>
            {{VULNERABILITIES}}
        </body>
        </html>
        """ 