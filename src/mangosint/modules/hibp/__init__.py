"""HaveIBeenPwned module for mangosint"""

import json
from typing import Any, Dict, List

from mangosint.core.config import Config
from mangosint.core.network import NetworkClient
from mangosint.modules.base import Module


class HIBPModule(Module):
    """HaveIBeenPwned breach data module"""

    def __init__(self, config: Config, network_client: NetworkClient):
        super().__init__(config, network_client)
        # HIBP API doesn't require a key for basic domain breach info
        self.api_key = getattr(config.api, 'hibp_api_key', None)

    @property
    def name(self) -> str:
        return "hibp"

    @property
    def description(self) -> str:
        return "HaveIBeenPwned breach data"

    @property
    def permissions(self) -> List[str]:
        return ["network", "api"]

    async def scan(self, target: str, target_type: str) -> Dict[str, Any]:
        """Perform HaveIBeenPwned breach check"""
        if target_type != "domain":
            return {"error": "HaveIBeenPwned only supports domain targets", "sources": ["hibp"], "module": "hibp", "confidence": 0.0}

        try:
            # Domain breach search
            url = f"https://haveibeenpwned.com/api/v3/breaches?domain={target}"

            headers = {"User-Agent": "mangosint-osint-tool"}
            if self.api_key:
                headers["hibp-api-key"] = self.api_key

            response = await self.network_client.get(url, headers=headers)

            if response.status_code == 200:
                data = response.json()

                breaches = []
                breached_emails = []

                for breach in data:
                    breach_info = {
                        "name": breach.get("Name", ""),
                        "title": breach.get("Title", ""),
                        "domain": breach.get("Domain", ""),
                        "breach_date": breach.get("BreachDate", ""),
                        "added_date": breach.get("AddedDate", ""),
                        "modified_date": breach.get("ModifiedDate", ""),
                        "pwn_count": breach.get("PwnCount", 0),
                        "description": breach.get("Description", ""),
                        "data_classes": breach.get("DataClasses", []),
                        "is_verified": breach.get("IsVerified", False),
                        "is_fabricated": breach.get("IsFabricated", False),
                        "is_sensitive": breach.get("IsSensitive", False),
                        "is_retired": breach.get("IsRetired", False),
                        "is_spam_list": breach.get("IsSpamList", False),
                        "logo_path": breach.get("LogoPath", "")
                    }
                    breaches.append(breach_info)

                return {
                    "breaches": breaches,
                    "breached_emails": breached_emails,
                    "sources": ["hibp"],
                    "confidence": 0.9,
                }

            elif response.status_code == 404:
                return {
                    "breaches": [],
                    "breached_emails": [],
                    "sources": ["hibp"],
                    "confidence": 0.9,
                }  # No breaches found is valid data
            elif response.status_code == 401:
                return {"error": "HaveIBeenPwned API key required for this request", "sources": ["hibp"], "module": "hibp", "confidence": 0.0}
            elif response.status_code == 429:
                return {"error": "HaveIBeenPwned rate limit exceeded", "sources": ["hibp"], "module": "hibp", "confidence": 0.0}
            else:
                return {"error": f"HaveIBeenPwned API error: {response.status_code}", "sources": ["hibp"], "module": "hibp", "confidence": 0.0}

        except Exception as e:
            return {"error": f"HaveIBeenPwned API error: {str(e)}", "sources": ["hibp"], "module": "hibp", "confidence": 0.0}