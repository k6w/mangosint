"""Shodan module for mangosint"""

import json
from typing import Any, Dict, List

from mangosint.core.config import Config
from mangosint.core.network import NetworkClient
from mangosint.modules.base import Module


class ShodanModule(Module):
    """Shodan internet scanner module"""

    def __init__(self, config: Config, network_client: NetworkClient):
        super().__init__(config, network_client)
        self.api_key = config.api.shodan_api_key

    @property
    def name(self) -> str:
        return "shodan"

    @property
    def description(self) -> str:
        return "Shodan internet-wide scanning data"

    @property
    def permissions(self) -> List[str]:
        return ["network", "api"]

    async def scan(self, target: str, target_type: str) -> Dict[str, Any]:
        """Perform Shodan scan"""
        if not self.api_key:
            return {"error": "Shodan API key not configured", "sources": ["shodan"], "module": "shodan", "confidence": 0.0}

        try:
            # Shodan API search
            if target_type == "ip":
                url = f"https://api.shodan.io/shodan/host/{target}"
                params = {"key": self.api_key}
            else:
                url = "https://api.shodan.io/shodan/host/search"
                params = {"key": self.api_key, "query": f"hostname:{target}", "limit": 10}

            response = await self.network_client.get(url, params=params)

            if response.status_code == 200:
                data = response.json()

                if target_type == "ip":
                    # Single host result
                    ports = data.get("ports", [])
                    hostnames = data.get("hostnames", [])
                    return {
                        "ports": ports,
                        "subdomains": hostnames,
                        "sources": ["shodan"],
                        "confidence": 0.8,
                    }
                else:
                    # Search results
                    matches = data.get("matches", [])
                    all_ports = []
                    all_hostnames = []

                    for match in matches[:10]:  # Limit to 10 results
                        all_ports.extend(match.get("ports", []))
                        all_hostnames.extend(match.get("hostnames", []))

                    return {
                        "ports": list(set(all_ports)),
                        "subdomains": list(set(all_hostnames)),
                        "sources": ["shodan"],
                        "confidence": 0.7,
                    }
            else:
                return {"error": f"Shodan API error: {response.status_code}", "sources": ["shodan"], "module": "shodan", "confidence": 0.0}

        except Exception as e:
            return {"error": str(e), "sources": ["shodan"], "module": "shodan", "confidence": 0.0}