"""
IDOR (Insecure Direct Object Reference) Vulnerability Detector
"""

from typing import List, Dict, Any, Optional
from src.core.models import APIEndpoint, Parameter
from src.core.http_client import HttpClient
import requests


class IDORDetector:
    """IDOR vulnerability detector"""
    
    def __init__(self):
        """Initialize IDOR detector"""
        self.id_patterns = [
            r'user_id', r'order_id', r'account_id', r'id', r'uid',
            r'user', r'account', r'order', r'item', r'product',
            r'file', r'document'
        ]
    
    def detect_id_parameters(self, endpoint: APIEndpoint) -> List[Parameter]:
        """Detect ID parameters in endpoint"""
        id_params = []
        for param in endpoint.parameters:
            if any(pattern in param.name.lower() for pattern in self.id_patterns):
                id_params.append(param)
        return id_params
    
    def generate_id_variations(self, original_id: Any) -> List[Any]:
        """Generate ID variations for testing"""
        variations = []
        
        # Try to convert to integer
        try:
            original_id_int = int(original_id)
            variations.extend([
                original_id_int + 1,      # +1
                original_id_int - 1,      # -1
                original_id_int + 10,     # +10
                original_id_int - 10,     # -10
                0,                       # 0
                -1                       # -1
            ])
        except (ValueError, TypeError):
            # If not integer, just add some common variations
            variations.extend([
                f"{original_id}_1",
                f"{original_id}_2",
                "1",
                "2"
            ])
        
        return variations
    
    def compare_responses(self, original: requests.Response, modified: requests.Response) -> Dict[str, Any]:
        """Compare two responses to detect differences"""
        differences = {
            "status_code": original.status_code != modified.status_code,
            "content_length": len(original.content) != len(modified.content),
            "content_similarity": len(original.content) == len(modified.content) and original.content == modified.content
        }
        
        # Calculate difference score (0-100)
        score = 0
        if differences["status_code"]:
            score += 50
        if differences["content_length"]:
            score += 30
        if not differences["content_similarity"]:
            score += 20
        
        differences["score"] = score
        return differences
    
    def detect_idor(self, endpoint: APIEndpoint, http_client: HttpClient) -> Dict[str, Any]:
        """Detect IDOR vulnerability in endpoint"""
        id_params = self.detect_id_parameters(endpoint)
        
        if not id_params:
            return {
                "is_vulnerable": False,
                "message": "No ID parameters found"
            }
        
        # Test each ID parameter
        results = []
        
        for param in id_params:
            # Get original response
            original_response = http_client.get(endpoint.url)
            
            # Generate variations
            original_value = param.default_value or 1
            variations = self.generate_id_variations(original_value)
            
            for variation in variations:
                # Create modified URL
                modified_url = endpoint.url.replace(str(original_value), str(variation))
                
                # Get modified response
                modified_response = http_client.get(modified_url)
                
                # Compare responses
                diff = self.compare_responses(original_response, modified_response)
                
                results.append({
                    "parameter": param.name,
                    "original_value": original_value,
                    "modified_value": variation,
                    "original_status": original_response.status_code,
                    "modified_status": modified_response.status_code,
                    "differences": diff
                })
        
        # Determine if vulnerable
        is_vulnerable = any(result["differences"]["score"] > 70 for result in results)
        
        return {
            "is_vulnerable": is_vulnerable,
            "results": results
        }
    
    def scan_endpoint(self, endpoint: APIEndpoint, http_client: HttpClient) -> List[Dict]:
        """Scan endpoint for IDOR vulnerabilities"""
        return [self.detect_idor(endpoint, http_client)]
    
    def scan_endpoints(self, endpoints: List[APIEndpoint], http_client: HttpClient) -> List[Dict]:
        """Scan multiple endpoints for IDOR vulnerabilities"""
        results = []
        for endpoint in endpoints:
            results.extend(self.scan_endpoint(endpoint, http_client))
        return results
