"""VirusTotal module for mangosint"""

from typing import Any, Dict, List

from mangosint.core.config import Config
from mangosint.core.network import NetworkClient
from mangosint.modules.base import Module


class VirusTotalModule(Module):
    """VirusTotal domain/IP analysis module"""

    def __init__(self, config: Config, network_client: NetworkClient):
        super().__init__(config, network_client)
        self.api_key = config.api.virustotal_api_key

    @property
    def name(self) -> str:
        return "virustotal"

    @property
    def description(self) -> str:
        return "VirusTotal domain and IP analysis"

    @property
    def permissions(self) -> List[str]:
        return ["network", "api"]

    async def scan(self, target: str, target_type: str) -> Dict[str, Any]:
        """Perform VirusTotal analysis"""
        if not self.api_key:
            return {"error": "VirusTotal API key not configured", "sources": ["virustotal"], "module": "virustotal", "confidence": 0.0}

        try:
            # VirusTotal API
            url = f"https://www.virustotal.com/api/v3/domains/{target}" if target_type == "domain" else f"https://www.virustotal.com/api/v3/ip_addresses/{target}"
            headers = {
                "x-apikey": self.api_key
            }

            response = await self.network_client.get(url, headers=headers)

            if response.status_code == 200:
                data = response.json()
                attributes = data.get("data", {}).get("attributes", {})

                result = {
                    "sources": ["virustotal"],
                    "confidence": 0.7,
                }

                # Extract reputation score
                if "last_analysis_stats" in attributes:
                    stats = attributes["last_analysis_stats"]
                    malicious = stats.get("malicious", 0)
                    total = sum(stats.values())
                    if total > 0:
                        reputation = (total - malicious) / total
                        result["reputation_score"] = reputation

                # Extract categories
                if "categories" in attributes:
                    result["categories"] = list(attributes["categories"].values())

                # Extract last analysis date
                if "last_analysis_date" in attributes:
                    result["last_analysis_date"] = attributes["last_analysis_date"]

                return result
            else:
                return {"error": f"VirusTotal API error: {response.status_code}", "sources": ["virustotal"], "module": "virustotal", "confidence": 0.0}

        except Exception as e:
            return {"error": str(e), "sources": ["virustotal"], "module": "virustotal", "confidence": 0.0}