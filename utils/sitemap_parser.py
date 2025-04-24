"""
Sitemap parser module for discovering URLs from XML sitemaps
"""

import xml.etree.ElementTree as ET
from typing import List, Optional
from urllib.parse import urljoin

import requests

class SitemapParser:
    """Parser for XML sitemaps"""
    
    def __init__(self, sitemap_url: str):
        """Initialize sitemap parser with sitemap URL"""
        self.sitemap_url = sitemap_url
        self.urls = []
        self.lastmod = {}
        self.changefreq = {}
        self.priority = {}
        
        # Parse sitemap
        self._parse_sitemap()
    
    def get_urls(self) -> List[str]:
        """Get list of discovered URLs"""
        return self.urls
    
    def get_lastmod(self, url: str) -> Optional[str]:
        """Get last modification date for URL"""
        return self.lastmod.get(url)
    
    def get_changefreq(self, url: str) -> Optional[str]:
        """Get change frequency for URL"""
        return self.changefreq.get(url)
    
    def get_priority(self, url: str) -> Optional[float]:
        """Get priority for URL"""
        return self.priority.get(url)
    
    def _parse_sitemap(self) -> None:
        """Parse sitemap XML"""
        try:
            # Fetch sitemap
            response = requests.get(self.sitemap_url, timeout=10)
            if not response.ok:
                return
            
            # Parse XML
            root = ET.fromstring(response.content)
            
            # Handle sitemap index
            if root.tag.endswith('sitemapindex'):
                for sitemap in root.findall('.//{*}loc'):
                    sub_sitemap_url = sitemap.text
                    sub_parser = SitemapParser(sub_sitemap_url)
                    self.urls.extend(sub_parser.get_urls())
                    self.lastmod.update(sub_parser.lastmod)
                    self.changefreq.update(sub_parser.changefreq)
                    self.priority.update(sub_parser.priority)
            
            # Handle URL list
            else:
                for url in root.findall('.//{*}url'):
                    loc = url.find('{*}loc')
                    if loc is not None and loc.text:
                        self.urls.append(loc.text)
                        
                        # Get lastmod
                        lastmod = url.find('{*}lastmod')
                        if lastmod is not None and lastmod.text:
                            self.lastmod[loc.text] = lastmod.text
                        
                        # Get changefreq
                        changefreq = url.find('{*}changefreq')
                        if changefreq is not None and changefreq.text:
                            self.changefreq[loc.text] = changefreq.text
                        
                        # Get priority
                        priority = url.find('{*}priority')
                        if priority is not None and priority.text:
                            try:
                                self.priority[loc.text] = float(priority.text)
                            except ValueError:
                                pass
            
        except Exception as e:
            print(f"Error parsing sitemap {self.sitemap_url}: {e}")
    
    def _normalize_url(self, url: str) -> str:
        """Normalize URL"""
        return urljoin(self.sitemap_url, url) 