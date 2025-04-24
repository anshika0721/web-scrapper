"""
WAF bypass module for handling various WAF evasion techniques
"""

import random
import string
import urllib.parse
from typing import List, Optional

class WAFBypass:
    """Handler for WAF bypass techniques"""
    
    def __init__(self):
        """Initialize WAF bypass handler"""
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
        ]
    
    def encode_payload(self, payload: str, encoding_type: str = "default") -> str:
        """
        Encode payload using various techniques
        
        Args:
            payload: Original payload to encode
            encoding_type: Type of encoding to apply
            
        Returns:
            Encoded payload
        """
        if encoding_type == "double_url":
            return urllib.parse.quote(urllib.parse.quote(payload))
        elif encoding_type == "hex":
            return "".join([f"%{ord(c):02x}" for c in payload])
        elif encoding_type == "unicode":
            return "".join([f"\\u{ord(c):04x}" for c in payload])
        elif encoding_type == "base64":
            import base64
            return base64.b64encode(payload.encode()).decode()
        else:
            return payload
    
    def get_random_user_agent(self) -> str:
        """Get a random user agent string"""
        return random.choice(self.user_agents)
    
    def generate_case_variants(self, payload: str) -> List[str]:
        """Generate case variants of a payload"""
        variants = [payload]
        
        # Add uppercase variant
        variants.append(payload.upper())
        
        # Add lowercase variant
        variants.append(payload.lower())
        
        # Add mixed case variant
        mixed = ""
        for i, c in enumerate(payload):
            if i % 2 == 0:
                mixed += c.upper()
            else:
                mixed += c.lower()
        variants.append(mixed)
        
        return variants
    
    def add_noise(self, payload: str, noise_chars: Optional[str] = None) -> str:
        """
        Add noise characters to payload
        
        Args:
            payload: Original payload
            noise_chars: Characters to use as noise (default: random alphanumeric)
            
        Returns:
            Payload with added noise
        """
        if noise_chars is None:
            noise_chars = string.ascii_letters + string.digits
        
        # Add random noise characters
        noisy_payload = ""
        for c in payload:
            noisy_payload += c
            if random.random() < 0.3:  # 30% chance to add noise
                noisy_payload += random.choice(noise_chars)
        
        return noisy_payload
    
    def wrap_payload(self, payload: str, wrapper: str = "default") -> str:
        """
        Wrap payload with various techniques
        
        Args:
            payload: Original payload
            wrapper: Type of wrapper to use
            
        Returns:
            Wrapped payload
        """
        if wrapper == "comment":
            return f"<!--{payload}-->"
        elif wrapper == "script":
            return f"<script>{payload}</script>"
        elif wrapper == "style":
            return f"<style>{payload}</style>"
        elif wrapper == "img":
            return f'<img src="x" onerror="{payload}">'
        else:
            return payload
    
    def generate_payload_variants(self, payload: str) -> List[str]:
        """Generate multiple variants of a payload using various techniques"""
        variants = []
        
        # Add original payload
        variants.append(payload)
        
        # Add case variants
        variants.extend(self.generate_case_variants(payload))
        
        # Add encoded variants
        variants.append(self.encode_payload(payload, "double_url"))
        variants.append(self.encode_payload(payload, "hex"))
        variants.append(self.encode_payload(payload, "unicode"))
        
        # Add wrapped variants
        variants.append(self.wrap_payload(payload, "comment"))
        variants.append(self.wrap_payload(payload, "script"))
        variants.append(self.wrap_payload(payload, "style"))
        
        # Add noisy variants
        variants.append(self.add_noise(payload))
        
        return list(set(variants))  # Remove duplicates 