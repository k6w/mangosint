"""CertSpotter module for mangosint"""

from typing import Any, Dict, List

from mangosint.core.config import Config
from mangosint.core.network import NetworkClient
from mangosint.modules.base import Module


class CertSpotterModule(Module):
    """CertSpotter certificate transparency module"""

    def __init__(self, config: Config, network_client: NetworkClient):
        super().__init__(config, network_client)
        self.base_url = "https://api.certspotter.com/v1"

    @property
    def name(self) -> str:
        return "certspotter"

    @property
    def description(self) -> str:
        return "CertSpotter certificate transparency monitoring"

    @property
    def permissions(self) -> List[str]:
        return ["network", "api"]

    async def scan(self, target: str, target_type: str) -> Dict[str, Any]:
        """Query CertSpotter for certificate transparency data"""
        if target_type not in ["domain"]:
            return {}

        api_key = self.config.api.certspotter_api_key or self.config.api.sslmate_api_key
        if not api_key:
            return {"error": "CertSpotter/SSLMate API key not configured", "sources": ["certspotter"], "confidence": 0.0}

        url = f"{self.base_url}/issuances"

        params = {
            "domain": target,
            "include_subdomains": "true",
            "expand": "dns_names,issuer,not_before,not_after"
        }

        headers = {
            "Authorization": f"Bearer {api_key}",
            "User-Agent": "mangosint/1.0"
        }

        try:
            response = await self.network_client.get(url, headers=headers, params=params)
            response.raise_for_status()
            data = response.json()

            # Extract certificate information
            certificates = []
            subdomains = []

            for cert in data[:20]:  # Limit results
                # Get detailed certificate info if available
                cert_detail = None
                try:
                    detail_url = f"{self.base_url}/{cert['id']}"
                    detail_response = await self.network_client.get(detail_url, headers=headers)
                    detail_response.raise_for_status()
                    cert_detail = detail_response.json()
                except:
                    cert_detail = cert  # Fall back to basic info

                cert_info = {
                    "id": cert.get("id"),
                    "dns_names": cert_detail.get("dns_names", []) if cert_detail else [],
                    "issuer": cert_detail.get("issuer", {}) if cert_detail else {},
                    "not_before": cert.get("not_before"),
                    "not_after": cert.get("not_after"),
                    "revoked": cert.get("revoked", False),
                    "cert_sha256": cert.get("cert_sha256"),
                }
                certificates.append(cert_info)

                # Extract subdomains from DNS names if available
                dns_names = cert_detail.get("dns_names", []) if cert_detail else []
                for dns_name in dns_names:
                    if dns_name != target and dns_name.endswith(f".{target}"):
                        subdomains.append(dns_name)

            return {
                "certificates": certificates,
                "subdomains": list(set(subdomains)),
                "sources": ["certspotter"],
                "confidence": 0.9,
            }

        except Exception as e:
            return {"error": str(e), "sources": ["certspotter"], "confidence": 0.0}