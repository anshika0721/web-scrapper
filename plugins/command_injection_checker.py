"""
Command injection vulnerability checker plugin
"""

import time
from typing import Dict, List, Optional

import requests

class CommandInjectionChecker:
    """Checker for command injection vulnerabilities"""
    
    def __init__(self):
        """Initialize command injection checker"""
        # Command injection payloads
        self.payloads = [
            "& ping -c 5 localhost &",
            "| ping -c 5 localhost |",
            "; ping -c 5 localhost ;",
            "` ping -c 5 localhost `",
            "$(ping -c 5 localhost)",
            "%0a ping -c 5 localhost %0a",
            "& sleep 5 &",
            "| sleep 5 |",
            "; sleep 5 ;",
            "` sleep 5 `",
            "$(sleep 5)",
            "%0a sleep 5 %0a",
            "& timeout 5 &",
            "| timeout 5 |",
            "; timeout 5 ;",
            "` timeout 5 `",
            "$(timeout 5)",
            "%0a timeout 5 %0a",
        ]
        
        # Windows-specific payloads
        self.windows_payloads = [
            "& ping -n 5 localhost &",
            "| ping -n 5 localhost |",
            "; ping -n 5 localhost ;",
            "` ping -n 5 localhost `",
            "$(ping -n 5 localhost)",
            "%0a ping -n 5 localhost %0a",
            "& timeout /t 5 &",
            "| timeout /t 5 |",
            "; timeout /t 5 ;",
            "` timeout /t 5 `",
            "$(timeout /t 5)",
            "%0a timeout /t 5 %0a",
        ]
        
        # Command output patterns
        self.output_patterns = [
            "bytes from localhost",
            "time=",
            "TTL=",
            "PING localhost",
            "Reply from",
            "packets transmitted",
            "packets received",
        ]
    
    def check(self, session: requests.Session, url: str, waf_bypass) -> Optional[Dict]:
        """
        Check for command injection vulnerabilities
        
        Args:
            session: Requests session
            url: Target URL
            waf_bypass: WAF bypass handler
            
        Returns:
            Dictionary with vulnerability details if found, None otherwise
        """
        try:
            # Find input points
            input_points = self._find_input_points(url)
            
            # Test each input point
            for point in input_points:
                # Test time-based command injection
                if self._test_time_based(session, point, waf_bypass):
                    return {
                        "type": "Command Injection",
                        "severity": "critical",
                        "url": url,
                        "evidence": f"Time-based command injection found in parameter: {point['param']}",
                        "description": "Command injection vulnerability allows attackers to execute arbitrary commands on the server."
                    }
                
                # Test output-based command injection
                if self._test_output_based(session, point, waf_bypass):
                    return {
                        "type": "Command Injection",
                        "severity": "critical",
                        "url": url,
                        "evidence": f"Output-based command injection found in parameter: {point['param']}",
                        "description": "Command injection vulnerability allows attackers to execute arbitrary commands and see their output."
                    }
            
            return None
            
        except Exception as e:
            print(f"Error checking command injection: {e}")
            return None
    
    def _find_input_points(self, url: str) -> List[Dict]:
        """Find potential input points for command injection testing"""
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
        
        return input_points
    
    def _test_time_based(self, session: requests.Session, point: Dict, waf_bypass) -> bool:
        """Test for time-based command injection"""
        try:
            if point['type'] == 'url':
                # Test each payload
                for payload in self.payloads + self.windows_payloads:
                    # Generate payload variants
                    payload_variants = waf_bypass.generate_payload_variants(payload)
                    
                    for variant in payload_variants:
                        # Test URL parameter
                        test_url = point['url'].replace(
                            f"{point['param']}={point['value']}", 
                            f"{point['param']}={variant}"
                        )
                        
                        # Measure response time
                        start_time = time.time()
                        response = session.get(test_url)
                        end_time = time.time()
                        
                        # Check if response time indicates successful injection
                        if response.ok and (end_time - start_time) >= 5:
                            return True
            
            return False
            
        except Exception:
            return False
    
    def _test_output_based(self, session: requests.Session, point: Dict, waf_bypass) -> bool:
        """Test for output-based command injection"""
        try:
            if point['type'] == 'url':
                # Test each payload
                for payload in self.payloads + self.windows_payloads:
                    # Generate payload variants
                    payload_variants = waf_bypass.generate_payload_variants(payload)
                    
                    for variant in payload_variants:
                        # Test URL parameter
                        test_url = point['url'].replace(
                            f"{point['param']}={point['value']}", 
                            f"{point['param']}={variant}"
                        )
                        
                        response = session.get(test_url)
                        if response.ok:
                            content = response.text
                            
                            # Check for command output patterns
                            for pattern in self.output_patterns:
                                if pattern.lower() in content.lower():
                                    return True
            
            return False
            
        except Exception:
            return False

# Create checker instance
checker = CommandInjectionChecker()

def check(session: requests.Session, url: str, waf_bypass) -> Optional[Dict]:
    """Check for command injection vulnerabilities"""
    return checker.check(session, url, waf_bypass) 
