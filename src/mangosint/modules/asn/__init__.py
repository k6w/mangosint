"""ASN lookup module for mangosint"""

from typing import Any, Dict, List

from mangosint.core.config import Config
from mangosint.core.network import NetworkClient
from mangosint.modules.base import Module


class ASNModule(Module):
    """ASN lookup module"""

    def __init__(self, config: Config, network_client: NetworkClient):
        super().__init__(config, network_client)

    @property
    def name(self) -> str:
        return "asn"

    @property
    def description(self) -> str:
        return "ASN and BGP information lookup"

    @property
    def permissions(self) -> List[str]:
        return ["network"]

    async def scan(self, target: str, target_type: str) -> Dict[str, Any]:
        """Perform ASN lookup"""
        if target_type not in ["ip", "domain"]:
            return {}

        try:
            # For domains, we need to resolve to IP first
            if target_type == "domain":
                # Simple DNS resolution to get an IP
                import socket
                try:
                    ip_address = socket.gethostbyname(target)
                    target = ip_address
                except socket.gaierror:
                    return {"error": f"DNS resolution failed for {target}", "sources": ["asn"], "module": "asn", "confidence": 0.0}

            # Use ipinfo.io for ASN lookup
            url = f"https://ipinfo.io/{target}/json"
            response = await self.network_client.get(url)

            if response.status_code == 200:
                data = response.json()

                # Return detailed IP information
                ip_detail = {
                    "address": target,
                    "asn": None,
                    "organization": None,
                    "isp": None,
                    "country": None,
                    "city": None,
                    "hostname": None
                }

                if "org" in data:
                    ip_detail["organization"] = data["org"]
                if "asn" in data:
                    asn_info = data["asn"]
                    if isinstance(asn_info, str):
                        ip_detail["asn"] = asn_info
                    elif isinstance(asn_info, dict):
                        ip_detail["asn"] = asn_info.get("asn")
                if "country" in data:
                    ip_detail["country"] = data["country"]
                if "city" in data:
                    ip_detail["city"] = data["city"]
                if "hostname" in data:
                    ip_detail["hostname"] = data["hostname"]

                return {
                    "ips": [ip_detail],
                    "sources": ["asn"],
                    "confidence": 0.8,
                }
            else:
                return {"error": f"ASN lookup failed: {response.status_code}", "sources": ["asn"], "module": "asn", "confidence": 0.0}

        except Exception as e:
            return {"error": str(e), "sources": ["asn"], "module": "asn", "confidence": 0.0}