"""URLScan.io module for mangosint"""

import json
from typing import Any, Dict, List

from mangosint.core.config import Config
from mangosint.core.network import NetworkClient
from mangosint.modules.base import Module


class URLScanModule(Module):
    """URLScan.io website scanner module"""

    def __init__(self, config: Config, network_client: NetworkClient):
        super().__init__(config, network_client)
        # URLScan.io has both free and paid APIs
        # Free API has rate limits but no key required
        self.api_key = getattr(config.api, 'urlscan_api_key', None)

    @property
    def name(self) -> str:
        return "urlscan"

    @property
    def description(self) -> str:
        return "URLScan.io website scanning data"

    @property
    def permissions(self) -> List[str]:
        return ["network", "api"]

    async def scan(self, target: str, target_type: str) -> Dict[str, Any]:
        """Perform URLScan.io scan"""
        if target_type not in ["domain", "url"]:
            return {"error": "URLScan.io only supports domain and URL targets", "sources": ["urlscan"], "module": "urlscan", "confidence": 0.0}

        try:
            # First, search for existing scans
            search_url = "https://urlscan.io/api/v1/search/"
            params = {"q": f"domain:{target}" if target_type == "domain" else f"url:{target}"}

            if self.api_key:
                headers = {"API-Key": self.api_key}
                response = await self.network_client.get(search_url, params=params, headers=headers)
            else:
                response = await self.network_client.get(search_url, params=params)

            if response.status_code == 200:
                data = response.json()
                results = data.get("results", [])

                if not results:
                    return {"error": "No URLScan.io results found for this target", "sources": ["urlscan"], "module": "urlscan", "confidence": 0.0}

                # Process the most recent result
                latest_result = results[0]
                result_url = latest_result.get("result")

                if result_url:
                    # Fetch detailed result
                    if self.api_key:
                        detail_response = await self.network_client.get(result_url, headers={"API-Key": self.api_key})
                    else:
                        detail_response = await self.network_client.get(result_url)

                    if detail_response.status_code == 200:
                        detail_data = detail_response.json()

                        technologies = []
                        security_headers = []
                        ips = []
                        certificates = []

                        # Extract page data
                        page = detail_data.get("page", {})
                        if "url" in page:
                            url = page["url"]
                            # Could extract more URL info here

                        # Extract technologies from page data
                        if "technologies" in page:
                            for tech in page["technologies"]:
                                tech_name = tech.get("name", "")
                                if tech_name and tech_name not in technologies:
                                    technologies.append(tech_name)

                        # Extract security headers
                        if "securityHeaders" in page:
                            sec_headers = page["securityHeaders"]
                            for header_name, header_value in sec_headers.items():
                                if header_value:  # Only include present headers
                                    security_headers.append(f"{header_name}: {header_value}")

                        # Extract IP from requests
                        requests = detail_data.get("requests", [])
                        for req in requests[:10]:  # Limit to first 10 requests
                            if "response" in req and "ip" in req["response"]:
                                ip = req["response"]["ip"]
                                if ip not in ips:
                                    ips.append(ip)

                        # Extract certificate info
                        if "certificate" in detail_data:
                            cert = detail_data["certificate"]
                            cert_info = {
                                "subject": cert.get("subject", {}),
                                "issuer": cert.get("issuer", {}),
                                "validity": cert.get("validity", {}),
                                "fingerprint": cert.get("fingerprint", "")
                            }
                            certificates.append(cert_info)

                        return {
                            "ips": ips,
                            "certificates": certificates,
                            "technologies": technologies,
                            "security_headers": security_headers,
                            "sources": ["urlscan"],
                            "confidence": 0.8,
                        }

                return {
                    "error": "Could not retrieve detailed URLScan.io result",
                    "sources": ["urlscan"],
                    "module": "urlscan",
                    "confidence": 0.0
                }

            elif response.status_code == 429:
                return {"error": "URLScan.io rate limit exceeded", "sources": ["urlscan"], "module": "urlscan", "confidence": 0.0}
            else:
                return {"error": f"URLScan.io API error: {response.status_code}", "sources": ["urlscan"], "module": "urlscan", "confidence": 0.0}

        except Exception as e:
            return {"error": f"URLScan.io API error: {str(e)}", "sources": ["urlscan"], "module": "urlscan", "confidence": 0.0}