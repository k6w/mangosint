"""HTTP metadata module for mangosint"""

from typing import Any, Dict, List
from urllib.parse import urlparse

from mangosint.core.config import Config
from mangosint.core.network import NetworkClient
from mangosint.modules.base import Module


class HTTPModule(Module):
    """HTTP metadata and header analysis module"""

    def __init__(self, config: Config, network_client: NetworkClient):
        super().__init__(config, network_client)

    @property
    def name(self) -> str:
        return "http"

    @property
    def description(self) -> str:
        return "HTTP headers and metadata analysis"

    @property
    def permissions(self) -> List[str]:
        return ["network", "active"]

    async def scan(self, target: str, target_type: str) -> Dict[str, Any]:
        """Perform HTTP analysis"""
        if target_type not in ["domain", "ip", "ip_port"]:
            return {}

        try:
            # Construct URL
            if target_type == "ip_port":
                host, port = target.rsplit(":", 1)
                url = f"http://{host}:{port}"
            elif target_type == "ip":
                url = f"http://{target}"
            else:
                url = f"http://{target}"

            # Try HTTPS first, then HTTP
            urls_to_try = [f"https://{target}", f"http://{target}"]

            for test_url in urls_to_try:
                try:
                    response = await self.network_client.get(test_url, follow_redirects=True)

                    if response.status_code < 400:  # Accept redirects and client errors as valid responses
                        headers = dict(response.headers)
                        result = {
                            "technologies": [],
                            "sources": ["http"],
                            "confidence": 0.7,
                        }

                        # Extract server information
                        server = headers.get("server", "").lower()
                        if server:
                            result["server"] = server

                        # Detect technologies from headers
                        techs = []

                        # Web servers
                        if "nginx" in server:
                            techs.append("nginx")
                        elif "apache" in server:
                            techs.append("apache")
                        elif "iis" in server:
                            techs.append("iis")

                        # Via header (proxies)
                        via = headers.get("via", "").lower()
                        if via:
                            if "cloudflare" in via:
                                techs.append("cloudflare")
                            elif "varnish" in via:
                                techs.append("varnish")

                        # X-Powered-By
                        powered_by = headers.get("x-powered-by", "").lower()
                        if powered_by:
                            if "php" in powered_by:
                                techs.append("php")
                            elif "asp.net" in powered_by:
                                techs.append("asp.net")

                        # Content-Type
                        content_type = headers.get("content-type", "").lower()
                        if "json" in content_type:
                            techs.append("api")

                        result["technologies"] = techs
                        return result

                except Exception:
                    continue

            return {"error": "No HTTP service detected", "sources": ["http"], "module": "http", "confidence": 0.0}

        except Exception as e:
            return {"error": str(e), "sources": ["http"], "module": "http", "confidence": 0.0}