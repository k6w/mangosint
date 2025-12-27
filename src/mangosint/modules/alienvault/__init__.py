"""AlienVault OTX module for mangosint"""

from typing import Any, Dict, List

from mangosint.core.config import Config
from mangosint.core.network import NetworkClient
from mangosint.modules.base import Module


class AlienVaultModule(Module):
    """AlienVault OTX module"""

    def __init__(self, config: Config, network_client: NetworkClient):
        super().__init__(config, network_client)
        self.base_url = "https://otx.alienvault.com/api/v1"

    @property
    def name(self) -> str:
        return "alienvault"

    @property
    def description(self) -> str:
        return "AlienVault Open Threat Exchange intelligence"

    @property
    def permissions(self) -> List[str]:
        return ["network", "api"]

    async def scan(self, target: str, target_type: str) -> Dict[str, Any]:
        """Query AlienVault OTX for intelligence"""
        if target_type not in ["ip", "domain"]:
            return {}

        api_key = self.config.api.alienvault_api_key
        if not api_key:
            return {"error": "AlienVault API key not configured", "module": "alienvault", "sources": ["alienvault"], "confidence": 0.0}

        # Map target_type to API endpoint format
        type_mapping = {
            "ip": "IPv4",  # API uses "IPv4" not "ip"
            "domain": "domain"
        }
        
        api_type = type_mapping.get(target_type)
        if not api_type:
            return {"error": f"Unsupported target type: {target_type}", "module": "alienvault", "sources": ["alienvault"], "confidence": 0.0}

        endpoint = f"/indicators/{api_type}/{target}/general"
        url = f"{self.base_url}{endpoint}"

        headers = {
            "X-OTX-API-KEY": api_key,
            "User-Agent": "mangosint/1.0"
        }

        try:
            response = await self.network_client.get(url, headers=headers)
            response.raise_for_status()
            data = response.json()

            # Extract relevant intelligence
            intelligence = {
                "sources": ["alienvault"],
                "confidence": 0.8,
            }

            if "pulse_info" in data:
                intelligence["threat_pulses"] = len(data["pulse_info"]["pulses"])
                intelligence["threat_tags"] = []
                for pulse in data["pulse_info"]["pulses"][:5]:  # Limit to first 5
                    if "tags" in pulse:
                        intelligence["threat_tags"].extend(pulse["tags"])

            if "validation" in data:
                intelligence["validation"] = data["validation"]

            return intelligence

        except Exception as e:
            return {"error": str(e), "module": "alienvault", "sources": ["alienvault"], "confidence": 0.0}