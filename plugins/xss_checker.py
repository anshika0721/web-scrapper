"""
XSS vulnerability checker plugin
"""

import re
from typing import Dict, List, Optional

import requests
from bs4 import BeautifulSoup

class XSSChecker:
    """Checker for Cross-Site Scripting (XSS) vulnerabilities"""
    
    def __init__(self):
        """Initialize XSS checker"""
        # XSS payloads
        self.payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "javascript:alert(1)",
            "\"><script>alert(1)</script>",
            "'><script>alert(1)</script>",
            "><script>alert(1)</script>",
            "</script><script>alert(1)</script>",
            "' onmouseover='alert(1)",
            "\" onmouseover=\"alert(1)",
            "' onfocus='alert(1)",
            "\" onfocus=\"alert(1)",
            "onerror=alert(1)",
            "onload=alert(1)",
            "onmouseover=alert(1)",
            "onfocus=alert(1)",
        ]
        
        # XSS detection patterns
        self.patterns = [
            r"<script>.*?</script>",
            r"javascript:",
            r"on\w+\s*=",
            r"<img[^>]+>",
            r"<svg[^>]+>",
            r"<iframe[^>]+>",
            r"<object[^>]+>",
            r"<embed[^>]+>",
        ]
    
    def check(self, session: requests.Session, url: str, waf_bypass) -> Optional[Dict]:
        """
        Check for XSS vulnerabilities
        
        Args:
            session: Requests session
            url: Target URL
            waf_bypass: WAF bypass handler
            
        Returns:
            Dictionary with vulnerability details if found, None otherwise
        """
        try:
            # Get original page content
            response = session.get(url)
            if not response.ok:
                return None
            
            original_content = response.text
            
            # Find input points
            input_points = self._find_input_points(url, original_content)
            
            # Test each input point
            for point in input_points:
                # Generate payload variants
                payload_variants = waf_bypass.generate_payload_variants(random.choice(self.payloads))
                
                for payload in payload_variants:
                    # Test reflected XSS
                    if self._test_reflected_xss(session, point, payload, original_content):
                        return {
                            "type": "XSS",
                            "severity": "high",
                            "url": url,
                            "evidence": f"Reflected XSS found in parameter: {point['param']}",
                            "description": "Cross-Site Scripting (XSS) vulnerability allows attackers to inject client-side scripts into web pages viewed by other users."
                        }
                    
                    # Test stored XSS
                    if self._test_stored_xss(session, point, payload):
                        return {
                            "type": "XSS",
                            "severity": "high",
                            "url": url,
                            "evidence": f"Stored XSS found in parameter: {point['param']}",
                            "description": "Stored Cross-Site Scripting (XSS) vulnerability allows attackers to inject malicious scripts that are permanently stored on the target server."
                        }
            
            return None
            
        except Exception as e:
            print(f"Error checking XSS: {e}")
            return None
    
    def _find_input_points(self, url: str, content: str) -> List[Dict]:
        """Find potential input points for XSS testing"""
        input_points = []
        
        # Parse URL parameters
        if "?" in url:
            base_url, params = url.split("?", 1)
            for param in params.split("&"):
                if "=" in param:
                    name, value = param.split("=", 1)
                    input_points.append({
                        "type": "url",
                        "param": name,
                        "value": value,
                        "url": url
                    })
        
        # Parse forms
        soup = BeautifulSoup(content, 'html.parser')
        for form in soup.find_all('form'):
            action = form.get('action', '')
            if not action:
                action = url
            
            for input_field in form.find_all(['input', 'textarea']):
                input_type = input_field.get('type', 'text')
                if input_type in ['text', 'search', 'url', 'email', 'tel', 'number']:
                    input_points.append({
                        "type": "form",
                        "param": input_field.get('name', ''),
                        "value": input_field.get('value', ''),
                        "url": action,
                        "method": form.get('method', 'get').lower()
                    })
        
        return input_points
    
    def _test_reflected_xss(self, session: requests.Session, point: Dict, payload: str, original_content: str) -> bool:
        """Test for reflected XSS"""
        try:
            if point['type'] == 'url':
                # Test URL parameter
                test_url = point['url'].replace(
                    f"{point['param']}={point['value']}", 
                    f"{point['param']}={payload}"
                )
                response = session.get(test_url)
                
            else:  # form
                # Prepare form data
                data = {point['param']: payload}
                
                # Submit form
                if point['method'] == 'post':
                    response = session.post(point['url'], data=data)
                else:
                    response = session.get(point['url'], params=data)
            
            # Check if payload is reflected
            if response.ok:
                content = response.text
                if payload in content and content != original_content:
                    # Verify payload is not just in comments or script tags
                    soup = BeautifulSoup(content, 'html.parser')
                    for pattern in self.patterns:
                        if re.search(pattern, str(soup), re.I):
                            return True
            
            return False
            
        except Exception:
            return False
    
    def _test_stored_xss(self, session: requests.Session, point: Dict, payload: str) -> bool:
        """Test for stored XSS"""
        try:
            if point['type'] == 'form':
                # Submit form with payload
                data = {point['param']: payload}
                if point['method'] == 'post':
                    session.post(point['url'], data=data)
                else:
                    session.get(point['url'], params=data)
                
                # Check if payload is stored
                response = session.get(point['url'])
                if response.ok and payload in response.text:
                    return True
            
            return False
            
        except Exception:
            return False

# Create checker instance
checker = XSSChecker()

def check(session: requests.Session, url: str, waf_bypass) -> Optional[Dict]:
    """Check for XSS vulnerabilities"""
    return checker.check(session, url, waf_bypass) 