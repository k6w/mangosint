"""GreyNoise module for mangosint"""

import json
from typing import Any, Dict, List

from mangosint.core.config import Config
from mangosint.core.network import NetworkClient
from mangosint.modules.base import Module


class GreyNoiseModule(Module):
    """GreyNoise IP context module"""

    def __init__(self, config: Config, network_client: NetworkClient):
        super().__init__(config, network_client)
        self.api_key = getattr(config.api, 'greynoise_api_key', None)

    @property
    def name(self) -> str:
        return "greynoise"

    @property
    def description(self) -> str:
        return "GreyNoise IP context and scanner intelligence"

    @property
    def permissions(self) -> List[str]:
        return ["network", "api"]

    async def scan(self, target: str, target_type: str) -> Dict[str, Any]:
        """Perform GreyNoise IP context lookup"""
        if target_type not in ["ip", "domain"]:
            return {"error": "GreyNoise only supports IP and domain targets", "sources": ["greynoise"], "module": "greynoise", "confidence": 0.0}

        try:
            headers = {}
            if self.api_key:
                headers["key"] = self.api_key

            if target_type == "ip":
                # IP context lookup
                url = f"https://api.greynoise.io/v3/community/{target}"
                response = await self.network_client.get(url, headers=headers)
            else:
                # Domain to IP resolution might be needed, but GreyNoise works with IPs
                return {"error": "GreyNoise requires IP addresses for context analysis", "sources": ["greynoise"], "module": "greynoise", "confidence": 0.0}

            if response.status_code == 200:
                data = response.json()

                # GreyNoise community API provides basic context
                ip_context = {
                    "ip": data.get("ip"),
                    "noise": data.get("noise"),  # Boolean: is this IP noisy (scanning)
                    "riot": data.get("riot"),    # Boolean: is this IP part of RIOT dataset
                    "classification": data.get("classification"),  # "unknown", "benign", "malicious"
                    "name": data.get("name"),    # Organization name if available
                    "link": data.get("link"),    # Link to GreyNoise visualizer
                    "last_seen": data.get("last_seen"),
                    "message": data.get("message")
                }

                return {
                    "ip_context": ip_context,
                    "sources": ["greynoise"],
                    "confidence": 0.8,
                }

            elif response.status_code == 404:
                # IP not found in GreyNoise data
                return {
                    "ip_context": {
                        "ip": target,
                        "noise": False,
                        "riot": False,
                        "classification": "unknown",
                        "message": "IP not found in GreyNoise dataset"
                    },
                    "sources": ["greynoise"],
                    "confidence": 0.8,
                }
            elif response.status_code == 429:
                return {"error": "GreyNoise API rate limit exceeded", "sources": ["greynoise"], "module": "greynoise", "confidence": 0.0}
            elif response.status_code == 401:
                return {"error": "GreyNoise API key invalid", "sources": ["greynoise"], "module": "greynoise", "confidence": 0.0}
            else:
                return {"error": f"GreyNoise API error: {response.status_code}", "sources": ["greynoise"], "module": "greynoise", "confidence": 0.0}

        except Exception as e:
            return {"error": f"GreyNoise API error: {str(e)}", "sources": ["greynoise"], "module": "greynoise", "confidence": 0.0}