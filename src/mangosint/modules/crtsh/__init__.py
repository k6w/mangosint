"""CRT.sh certificate module for mangosint"""

import json
from typing import Any, Dict, List

from mangosint.core.config import Config
from mangosint.core.network import NetworkClient
from mangosint.modules.base import Module


class CRTModule(Module):
    """CRT.sh certificate transparency module"""

    def __init__(self, config: Config, network_client: NetworkClient):
        super().__init__(config, network_client)

    @property
    def name(self) -> str:
        return "crtsh"

    @property
    def description(self) -> str:
        return "Certificate Transparency logs from crt.sh"

    @property
    def permissions(self) -> List[str]:
        return ["network"]

    async def scan(self, target: str, target_type: str) -> Dict[str, Any]:
        """Perform CRT.sh scan"""
        if target_type != "domain":
            return {}

        try:
            # CRT.sh API
            url = f"https://crt.sh/?q={target}&output=json"

            response = await self.network_client.get(url)

            if response.status_code == 200:
                certs = response.json()

                subdomains = set()
                certificates = []

                for cert in certs:
                    if "name_value" in cert:
                        names = cert["name_value"].split("\n")
                        for name in names:
                            name = name.strip()
                            if name and "*" not in name:  # Skip wildcards for now
                                subdomains.add(name)

                    certificates.append({
                        "issuer": cert.get("issuer_name", ""),
                        "subject": cert.get("name_value", ""),
                        "not_before": cert.get("not_before", ""),
                        "not_after": cert.get("not_after", ""),
                    })

                return {
                    "subdomains": list(subdomains),
                    "certificates": certificates[:10],  # Limit to 10
                    "sources": ["crtsh"],
                    "confidence": 0.9,
                }
            else:
                return {"error": f"CRT.sh API error: {response.status_code}", "sources": ["crtsh"], "confidence": 0.0}

        except Exception as e:
            return {"error": str(e), "sources": ["crtsh"], "confidence": 0.0}