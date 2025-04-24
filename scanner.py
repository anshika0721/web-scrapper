#!/usr/bin/env python3
"""
Web Application Vulnerability Scanner
Main scanner module implementing core scanning functionality
"""

import argparse
import json
import logging
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional, Set, Union
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
from tqdm import tqdm

from plugins import (
    xss_checker,
    sql_injection_checker,
    command_injection_checker,
    ssrf_checker,
    lfi_checker,
    directory_traversal_checker,
    open_redirect_checker,
    clickjacking_checker,
    header_checker,
)
from utils.auth import AuthHandler
from utils.crawler import Crawler
from utils.reporter import Reporter
from utils.tech_detector import TechnologyDetector
from utils.waf_bypass import WAFBypass

# Initialize colorama
init()

class Scanner:
    """Main scanner class implementing vulnerability scanning functionality"""
    
    def __init__(
        self,
        target_url: str,
        depth: int = 3,
        threads: int = 10,
        delay: float = 1.0,
        timeout: int = 30,
        cookies: Optional[str] = None,
        auth_url: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        proxy: Optional[str] = None,
        burp_proxy: Optional[str] = None,
        output_file: Optional[str] = None,
    ):
        """Initialize the scanner with configuration parameters"""
        self.target_url = target_url
        self.depth = depth
        self.threads = threads
        self.delay = delay
        self.timeout = timeout
        self.output_file = output_file
        
        # Initialize components
        self.session = requests.Session()
        self.crawler = Crawler(self.session, depth)
        self.auth_handler = AuthHandler(self.session)
        self.reporter = Reporter()
        self.tech_detector = TechnologyDetector()
        self.waf_bypass = WAFBypass()
        
        # Configure session
        if cookies:
            self._parse_cookies(cookies)
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}
        if burp_proxy:
            self.session.proxies = {"http": burp_proxy, "https": burp_proxy}
            self.session.verify = False
        
        # Handle authentication if provided
        if auth_url and username and password:
            self.auth_handler.login(auth_url, username, password)
    
    def _parse_cookies(self, cookie_string: str) -> None:
        """Parse and set cookies from string"""
        try:
            cookie_dict = {}
            for cookie in cookie_string.split(";"):
                if "=" in cookie:
                    name, value = cookie.strip().split("=", 1)
                    cookie_dict[name] = value
            self.session.cookies.update(cookie_dict)
        except Exception as e:
            logging.error(f"Error parsing cookies: {e}")
    
    def scan(self) -> Dict:
        """Perform the vulnerability scan"""
        print(f"{Fore.BLUE}[*] Starting scan of {self.target_url}{Style.RESET_ALL}")
        
        # Initialize results
        results = {
            "target_url": self.target_url,
            "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "vulnerabilities": [],
            "technologies": [],
            "endpoints": []
        }
        
        # Crawl the website
        print(f"{Fore.BLUE}[*] Crawling website...{Style.RESET_ALL}")
        endpoints = self.crawler.crawl(self.target_url)
        results["endpoints"] = list(endpoints)
        
        # Detect technologies
        print(f"{Fore.BLUE}[*] Detecting technologies...{Style.RESET_ALL}")
        results["technologies"] = self.tech_detector.detect(self.target_url)
        
        # Run vulnerability checks
        print(f"{Fore.BLUE}[*] Running vulnerability checks...{Style.RESET_ALL}")
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            for endpoint in endpoints:
                futures.extend([
                    executor.submit(self._check_endpoint, endpoint, checker)
                    for checker in self._get_checkers()
                ])
            
            for future in tqdm(futures, desc="Scanning"):
                result = future.result()
                if result:
                    results["vulnerabilities"].append(result)
        
        # Save results if output file specified
        if self.output_file:
            self.reporter.save_results(results, self.output_file)
        
        return results
    
    def _get_checkers(self) -> List:
        """Return list of vulnerability checkers"""
        return [
            xss_checker.check,
            sql_injection_checker.check,
            command_injection_checker.check,
            ssrf_checker.check,
            lfi_checker.check,
            directory_traversal_checker.check,
            open_redirect_checker.check,
            clickjacking_checker.check,
            header_checker.check,
        ]
    
    def _check_endpoint(self, endpoint: str, checker: callable) -> Optional[Dict]:
        """Run a specific vulnerability check on an endpoint"""
        try:
            time.sleep(self.delay)  # Respect delay between requests
            return checker(self.session, endpoint, self.waf_bypass)
        except Exception as e:
            logging.error(f"Error checking {endpoint}: {e}")
            return None

def main():
    """Main entry point for the scanner"""
    parser = argparse.ArgumentParser(description="Web Application Vulnerability Scanner")
    parser.add_argument("--url", required=True, help="Target URL to scan")
    parser.add_argument("--depth", type=int, default=3, help="Crawling depth")
    parser.add_argument("--threads", type=int, default=10, help="Number of concurrent threads")
    parser.add_argument("--delay", type=float, default=1.0, help="Delay between requests")
    parser.add_argument("--timeout", type=int, default=30, help="Request timeout")
    parser.add_argument("--cookie", help="Cookie string")
    parser.add_argument("--auth-url", help="Authentication URL")
    parser.add_argument("--username", help="Username for authentication")
    parser.add_argument("--password", help="Password for authentication")
    parser.add_argument("--proxy", help="Proxy URL")
    parser.add_argument("--burp-proxy", help="Burp Suite proxy URL")
    parser.add_argument("--output", help="Output file for results")
    
    args = parser.parse_args()
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )
    
    try:
        scanner = Scanner(
            target_url=args.url,
            depth=args.depth,
            threads=args.threads,
            delay=args.delay,
            timeout=args.timeout,
            cookies=args.cookie,
            auth_url=args.auth_url,
            username=args.username,
            password=args.password,
            proxy=args.proxy,
            burp_proxy=args.burp_proxy,
            output_file=args.output,
        )
        
        results = scanner.scan()
        
        # Print summary
        print(f"\n{Fore.GREEN}Scan completed!{Style.RESET_ALL}")
        print(f"Found {len(results['vulnerabilities'])} vulnerabilities")
        print(f"Detected {len(results['technologies'])} technologies")
        print(f"Scanned {len(results['endpoints'])} endpoints")
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Fore.RED}Error: {e}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == "__main__":
    main() 