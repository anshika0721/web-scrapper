"""
Technology detector module for identifying web technologies and frameworks
"""

import json
import logging
from typing import Dict, List, Set

import requests
from bs4 import BeautifulSoup

class TechnologyDetector:
    """Detector for identifying web technologies and frameworks"""
    
    def __init__(self):
        """Initialize technology detector"""
        # Common technology signatures
        self.server_signatures = {
            "Apache": ["Apache", "mod_", "X-Powered-By: Apache"],
            "Nginx": ["nginx", "X-Powered-By: nginx"],
            "IIS": ["Microsoft-IIS", "X-Powered-By: ASP.NET"],
            "Tomcat": ["Apache-Coyote", "X-Powered-By: JSP"],
        }
        
        self.framework_signatures = {
            "Django": ["csrfmiddlewaretoken", "__admin__"],
            "Flask": ["flask-session", "Werkzeug"],
            "Laravel": ["laravel_session", "XSRF-TOKEN"],
            "Rails": ["_rails", "csrf-token"],
            "Spring": ["JSESSIONID", "org.springframework"],
            "Express": ["express", "connect.sid"],
            "ASP.NET": ["ASP.NET", "__VIEWSTATE"],
            "WordPress": ["wp-content", "wp-includes"],
            "Drupal": ["Drupal", "drupal.js"],
            "Joomla": ["joomla", "mod_"],
        }
        
        self.cms_signatures = {
            "WordPress": ["wp-content", "wp-includes"],
            "Drupal": ["Drupal", "drupal.js"],
            "Joomla": ["joomla", "mod_"],
            "Magento": ["Magento", "skin/frontend"],
            "Shopify": ["shopify", "myshopify.com"],
        }
    
    def detect(self, url: str) -> List[Dict]:
        """
        Detect technologies used by the website
        
        Args:
            url: Target URL to analyze
            
        Returns:
            List of detected technologies with confidence levels
        """
        try:
            # Make request
            response = requests.get(url, timeout=30)
            if not response.ok:
                return []
            
            # Initialize results
            detected = []
            
            # Check headers
            headers = response.headers
            for tech, signatures in self.server_signatures.items():
                if self._check_signatures(headers, signatures):
                    detected.append({
                        "type": "server",
                        "name": tech,
                        "confidence": "high",
                        "evidence": self._get_evidence(headers, signatures)
                    })
            
            # Check HTML content
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Check meta tags
            meta_tags = soup.find_all('meta')
            for tag in meta_tags:
                content = tag.get('content', '').lower()
                name = tag.get('name', '').lower()
                
                # Check generator meta tag
                if name == 'generator':
                    detected.append({
                        "type": "framework",
                        "name": content,
                        "confidence": "high",
                        "evidence": f"Meta generator tag: {content}"
                    })
            
            # Check framework signatures
            for framework, signatures in self.framework_signatures.items():
                if self._check_signatures(response.text, signatures):
                    detected.append({
                        "type": "framework",
                        "name": framework,
                        "confidence": "medium",
                        "evidence": self._get_evidence(response.text, signatures)
                    })
            
            # Check CMS signatures
            for cms, signatures in self.cms_signatures.items():
                if self._check_signatures(response.text, signatures):
                    detected.append({
                        "type": "cms",
                        "name": cms,
                        "confidence": "medium",
                        "evidence": self._get_evidence(response.text, signatures)
                    })
            
            # Check JavaScript files
            scripts = soup.find_all('script', src=True)
            for script in scripts:
                src = script['src'].lower()
                if 'jquery' in src:
                    detected.append({
                        "type": "library",
                        "name": "jQuery",
                        "confidence": "high",
                        "evidence": f"Script source: {src}"
                    })
                elif 'bootstrap' in src:
                    detected.append({
                        "type": "library",
                        "name": "Bootstrap",
                        "confidence": "high",
                        "evidence": f"Script source: {src}"
                    })
            
            return detected
            
        except Exception as e:
            logging.error(f"Technology detection failed: {e}")
            return []
    
    def _check_signatures(self, content: str, signatures: List[str]) -> bool:
        """Check if any signatures match the content"""
        return any(sig.lower() in content.lower() for sig in signatures)
    
    def _get_evidence(self, content: str, signatures: List[str]) -> str:
        """Get evidence of matched signature"""
        for sig in signatures:
            if sig.lower() in content.lower():
                return f"Found signature: {sig}"
        return "" 