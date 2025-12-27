"""HTTP Security Headers module for mangosint"""

from typing import Any, Dict, List

from mangosint.core.config import Config
from mangosint.core.network import NetworkClient
from mangosint.modules.base import Module


class HTTPSecurityModule(Module):
    """HTTP security headers analysis module"""

    def __init__(self, config: Config, network_client: NetworkClient):
        super().__init__(config, network_client)

    @property
    def name(self) -> str:
        return "security"

    @property
    def description(self) -> str:
        return "HTTP security headers and configuration analysis"

    @property
    def permissions(self) -> List[str]:
        return ["network", "active"]

    def _analyze_security_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Analyze security headers and provide recommendations"""
        analysis = {
            "security_score": 0,
            "missing_headers": [],
            "present_headers": [],
            "recommendations": [],
            "issues": [],
        }

        # Essential security headers to check
        essential_headers = {
            "Strict-Transport-Security": "HSTS",
            "Content-Security-Policy": "CSP",
            "X-Frame-Options": "Clickjacking protection",
            "X-Content-Type-Options": "MIME sniffing protection",
            "Referrer-Policy": "Referrer control",
            "Permissions-Policy": "Feature policy",
        }

        # Important security headers
        important_headers = {
            "X-XSS-Protection": "XSS protection",
            "Expect-CT": "Certificate transparency",
        }

        # Check essential headers
        for header, description in essential_headers.items():
            if header in headers:
                analysis["present_headers"].append({"header": header, "description": description})
                analysis["security_score"] += 20
            else:
                analysis["missing_headers"].append({"header": header, "description": description, "importance": "essential"})
                analysis["recommendations"].append(f"Add {header} header for {description.lower()}")

        # Check important headers
        for header, description in important_headers.items():
            if header in headers:
                analysis["present_headers"].append({"header": header, "description": description})
                analysis["security_score"] += 10
            else:
                analysis["missing_headers"].append({"header": header, "description": description, "importance": "important"})

        # Analyze specific headers
        if "Strict-Transport-Security" in headers:
            hsts_value = headers["Strict-Transport-Security"]
            if "max-age=" in hsts_value:
                max_age = hsts_value.split("max-age=")[1].split(";")[0]
                try:
                    max_age_seconds = int(max_age)
                    if max_age_seconds < 31536000:  # Less than 1 year
                        analysis["issues"].append("HSTS max-age is less than recommended 1 year")
                except:
                    pass

        if "Content-Security-Policy" in headers:
            csp_value = headers["Content-Security-Policy"]
            if "'unsafe-inline'" in csp_value or "'unsafe-eval'" in csp_value:
                analysis["issues"].append("CSP allows unsafe inline scripts or eval")

        if "X-Frame-Options" in headers:
            xfo_value = headers["X-Frame-Options"].upper()
            if xfo_value not in ["DENY", "SAMEORIGIN"]:
                analysis["issues"].append("X-Frame-Options should be DENY or SAMEORIGIN")

        # Server header analysis
        if "server" in headers:
            server = headers["server"].lower()
            if "apache" in server and "2.4" not in server:
                analysis["issues"].append("Apache version might be outdated")
            elif "nginx" in server and "1." in server:
                analysis["issues"].append("Nginx version might be outdated")

        # Cookies analysis
        if "set-cookie" in headers:
            cookies = headers.get("set-cookie", "")
            if "secure" not in cookies.lower():
                analysis["issues"].append("Cookies should have Secure flag")
            if "httponly" not in cookies.lower():
                analysis["issues"].append("Cookies should have HttpOnly flag")
            if "samesite" not in cookies.lower():
                analysis["issues"].append("Cookies should have SameSite attribute")

        return analysis

    async def scan(self, target: str, target_type: str) -> Dict[str, Any]:
        """Perform HTTP security analysis"""
        if target_type not in ["domain", "ip"]:
            return {}

        try:
            # Construct URLs to try
            urls_to_try = []
            if target_type == "domain":
                urls_to_try = [f"https://{target}", f"http://{target}"]
            else:  # ip
                urls_to_try = [f"https://{target}", f"http://{target}"]

            for url in urls_to_try:
                try:
                    response = await self.network_client.get(url, follow_redirects=True)

                    if response.status_code < 400:  # Accept redirects and client errors
                        headers = dict(response.headers)

                        analysis = self._analyze_security_headers(headers)

                        return {
                            "security_headers": headers,
                            "security_analysis": analysis,
                            "response_code": response.status_code,
                            "final_url": str(response.url),
                            "sources": ["security"],
                            "confidence": 0.8,
                        }

                except Exception:
                    continue

            return {"error": "Could not connect to target", "sources": ["security"], "confidence": 0.0}

        except Exception as e:
            return {
                "error": str(e),
                "sources": ["security"],
                "confidence": 0.0,
            }