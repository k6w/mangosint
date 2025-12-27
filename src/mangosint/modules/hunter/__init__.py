"""Hunter.io module for mangosint"""

import json
from typing import Any, Dict, List

from mangosint.core.config import Config
from mangosint.core.network import NetworkClient
from mangosint.modules.base import Module


class HunterModule(Module):
    """Hunter.io email discovery module"""

    def __init__(self, config: Config, network_client: NetworkClient):
        super().__init__(config, network_client)
        self.api_key = getattr(config.api, 'hunter_api_key', None)

    @property
    def name(self) -> str:
        return "hunter"

    @property
    def description(self) -> str:
        return "Hunter.io email discovery"

    @property
    def permissions(self) -> List[str]:
        return ["network", "api"]

    async def scan(self, target: str, target_type: str) -> Dict[str, Any]:
        """Perform Hunter.io email discovery"""
        if not self.api_key:
            return {"error": "Hunter.io API key not configured", "sources": ["hunter"], "module": "hunter", "confidence": 0.0}

        if target_type != "domain":
            return {"error": "Hunter.io only supports domain targets for email discovery", "sources": ["hunter"], "module": "hunter", "confidence": 0.0}

        try:
            # Domain search for email addresses
            url = "https://api.hunter.io/v2/domain-search"
            params = {
                "domain": target,
                "api_key": self.api_key
            }

            response = await self.network_client.get(url, params=params)

            if response.status_code == 200:
                data = response.json()
                domain_data = data.get("data", {})

                emails = []
                patterns = []

                # Extract email addresses
                email_list = domain_data.get("emails", [])
                for email_info in email_list:
                    email = email_info.get("value", "")
                    if email:
                        emails.append({
                            "email": email,
                            "first_name": email_info.get("first_name", ""),
                            "last_name": email_info.get("last_name", ""),
                            "position": email_info.get("position", ""),
                            "linkedin_url": email_info.get("linkedin_url", ""),
                            "twitter": email_info.get("twitter", ""),
                            "phone_number": email_info.get("phone_number", "")
                        })

                # Extract email patterns
                pattern_list = domain_data.get("pattern", "")
                if pattern_list:
                    patterns.append(pattern_list)

                return {
                    "emails": emails,
                    "email_patterns": patterns,
                    "sources": ["hunter"],
                    "confidence": 0.8,
                }

            elif response.status_code == 401:
                return {"error": "Hunter.io API key invalid", "sources": ["hunter"], "module": "hunter", "confidence": 0.0}
            elif response.status_code == 403:
                return {"error": "Hunter.io API quota exceeded", "sources": ["hunter"], "module": "hunter", "confidence": 0.0}
            else:
                return {"error": f"Hunter.io API error: {response.status_code}", "sources": ["hunter"], "module": "hunter", "confidence": 0.0}

        except Exception as e:
            return {"error": f"Hunter.io API error: {str(e)}", "sources": ["hunter"], "module": "hunter", "confidence": 0.0}