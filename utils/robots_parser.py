"""
Robots.txt parser module for respecting crawling rules
"""

import re
from typing import List, Optional
from urllib.parse import urljoin, urlparse

import requests

class RobotsParser:
    """Parser for robots.txt files"""
    
    def __init__(self, base_url: str):
        """Initialize robots parser with base URL"""
        self.base_url = base_url
        self.allowed_paths = []
        self.disallowed_paths = []
        self.crawl_delay = 1.0
        self.sitemap_urls = []
        
        # Parse robots.txt
        self._parse_robots_txt()
    
    def is_allowed(self, url: str) -> bool:
        """
        Check if URL is allowed by robots.txt
        
        Args:
            url: URL to check
            
        Returns:
            bool: True if URL is allowed, False otherwise
        """
        try:
            # Parse URL
            parsed = urlparse(url)
            path = parsed.path
            
            # Check if path is disallowed
            for disallowed in self.disallowed_paths:
                if path.startswith(disallowed):
                    return False
            
            # Check if path is explicitly allowed
            for allowed in self.allowed_paths:
                if path.startswith(allowed):
                    return True
            
            # If no explicit rules, allow by default
            return True
            
        except Exception:
            return True  # Allow on error
    
    def get_crawl_delay(self) -> float:
        """Get crawl delay in seconds"""
        return self.crawl_delay
    
    def get_sitemap_urls(self) -> List[str]:
        """Get list of sitemap URLs"""
        return self.sitemap_urls
    
    def _parse_robots_txt(self) -> None:
        """Parse robots.txt file"""
        try:
            # Get robots.txt URL
            robots_url = urljoin(self.base_url, '/robots.txt')
            
            # Fetch robots.txt
            response = requests.get(robots_url, timeout=10)
            if not response.ok:
                return
            
            # Parse content
            content = response.text
            current_user_agent = None
            
            for line in content.splitlines():
                line = line.strip().lower()
                
                # Skip empty lines and comments
                if not line or line.startswith('#'):
                    continue
                
                # Parse directives
                if line.startswith('user-agent:'):
                    current_user_agent = line.split(':', 1)[1].strip()
                elif line.startswith('allow:'):
                    if current_user_agent in ['*', 'python-requests']:
                        path = line.split(':', 1)[1].strip()
                        self.allowed_paths.append(path)
                elif line.startswith('disallow:'):
                    if current_user_agent in ['*', 'python-requests']:
                        path = line.split(':', 1)[1].strip()
                        self.disallowed_paths.append(path)
                elif line.startswith('crawl-delay:'):
                    if current_user_agent in ['*', 'python-requests']:
                        try:
                            delay = float(line.split(':', 1)[1].strip())
                            self.crawl_delay = max(self.crawl_delay, delay)
                        except ValueError:
                            pass
                elif line.startswith('sitemap:'):
                    sitemap_url = line.split(':', 1)[1].strip()
                    self.sitemap_urls.append(sitemap_url)
            
        except Exception as e:
            print(f"Error parsing robots.txt: {e}")
    
    def _normalize_path(self, path: str) -> str:
        """Normalize path for comparison"""
        # Remove trailing slash
        if path.endswith('/'):
            path = path[:-1]
        
        # Add leading slash
        if not path.startswith('/'):
            path = '/' + path
        
        return path 