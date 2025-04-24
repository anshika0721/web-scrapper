"""
Web crawler module for recursively discovering endpoints
"""

import logging
from typing import Set
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from robots_parser import RobotsParser

class Crawler:
    """Crawler class for discovering endpoints"""
    
    def __init__(self, session: requests.Session, max_depth: int = 3):
        """Initialize crawler with session and max depth"""
        self.session = session
        self.max_depth = max_depth
        self.visited = set()
        self.robots_parser = None
    
    def crawl(self, start_url: str) -> Set[str]:
        """Crawl website starting from given URL"""
        self.visited.clear()
        self.robots_parser = RobotsParser(start_url)
        
        # Normalize start URL
        start_url = self._normalize_url(start_url)
        
        # Start crawling
        self._crawl_url(start_url, depth=0)
        
        return self.visited
    
    def _crawl_url(self, url: str, depth: int) -> None:
        """Recursively crawl URL up to max depth"""
        if depth > self.max_depth or url in self.visited:
            return
        
        # Check robots.txt
        if not self.robots_parser.is_allowed(url):
            logging.debug(f"URL not allowed by robots.txt: {url}")
            return
        
        try:
            # Add to visited set
            self.visited.add(url)
            
            # Make request
            response = self.session.get(url, timeout=30)
            if not response.ok:
                return
            
            # Parse links
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find all links
            for link in soup.find_all(['a', 'form']):
                new_url = self._extract_url(link, url)
                if new_url:
                    self._crawl_url(new_url, depth + 1)
            
            # Find JavaScript files
            for script in soup.find_all('script', src=True):
                new_url = urljoin(url, script['src'])
                if new_url:
                    self._crawl_url(new_url, depth + 1)
            
        except Exception as e:
            logging.error(f"Error crawling {url}: {e}")
    
    def _extract_url(self, element, base_url: str) -> str:
        """Extract URL from HTML element"""
        if element.name == 'a':
            href = element.get('href')
            if href:
                return urljoin(base_url, href)
        elif element.name == 'form':
            action = element.get('action')
            if action:
                return urljoin(base_url, action)
        return None
    
    def _normalize_url(self, url: str) -> str:
        """Normalize URL by removing fragments and query parameters"""
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}" 