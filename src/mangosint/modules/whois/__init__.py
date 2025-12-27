"""Whois module for mangosint"""

import re
from typing import Any, Dict, List

from mangosint.core.config import Config
from mangosint.core.network import NetworkClient
from mangosint.modules.base import Module


class WhoisModule(Module):
    """Whois lookup module"""

    def __init__(self, config: Config, network_client: NetworkClient):
        super().__init__(config, network_client)

    @property
    def name(self) -> str:
        return "whois"

    @property
    def description(self) -> str:
        return "Whois domain registration information"

    @property
    def permissions(self) -> List[str]:
        return ["network"]

    async def scan(self, target: str, target_type: str) -> Dict[str, Any]:
        """Perform Whois lookup"""
        if target_type != "domain":
            return {}

        try:
            # Use whois.com API or similar
            url = f"https://www.whois.com/whois/{target}"

            response = await self.network_client.get(url)

            if response.status_code == 200:
                # Parse the HTML response for whois data
                html = response.text

                # Extract basic information
                organization = None
                registrar = None
                creation_date = None
                expiry_date = None

                # Simple regex parsing (in production, use proper HTML parser)
                # Look for specific patterns in the whois data
                org_match = re.search(r"Registrant Organization:\s*([^<\n\r]+)", html, re.IGNORECASE)
                if not org_match:
                    org_match = re.search(r"Organization:\s*([^<\n\r]+)", html, re.IGNORECASE)
                if org_match:
                    organization = re.sub(r'<[^>]+>', '', org_match.group(1).strip())  # Remove HTML tags

                registrar_match = re.search(r"Registrar:\s*([^<\n\r]+)", html, re.IGNORECASE)
                if registrar_match:
                    registrar = re.sub(r'<[^>]+>', '', registrar_match.group(1).strip())

                created_match = re.search(r"Creation Date:\s*([^<\n\r]+)", html, re.IGNORECASE)
                if created_match:
                    creation_date = re.sub(r'<[^>]+>', '', created_match.group(1).strip())

                expiry_match = re.search(r"Registry Expiry Date:\s*([^<\n\r]+)", html, re.IGNORECASE)
                if expiry_match:
                    expiry_date = re.sub(r'<[^>]+>', '', expiry_match.group(1).strip())

                result = {
                    "sources": ["whois"],
                    "confidence": 0.6,
                }

                if organization:
                    result["organization"] = organization
                if registrar:
                    result["registrar"] = registrar
                if creation_date:
                    result["creation_date"] = creation_date
                if expiry_date:
                    result["expiry_date"] = expiry_date

                return result
            else:
                return {"error": f"Whois lookup failed: {response.status_code}", "sources": ["whois"], "confidence": 0.0}

        except Exception as e:
            return {"error": str(e), "sources": ["whois"], "confidence": 0.0}