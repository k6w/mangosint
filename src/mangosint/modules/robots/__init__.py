"""Robots.txt module for mangosint"""

from typing import Any, Dict, List

from mangosint.core.config import Config
from mangosint.core.network import NetworkClient
from mangosint.modules.base import Module


class RobotsModule(Module):
    """Robots.txt analysis module"""

    def __init__(self, config: Config, network_client: NetworkClient):
        super().__init__(config, network_client)

    @property
    def name(self) -> str:
        return "robots"

    @property
    def description(self) -> str:
        return "Robots.txt analysis and crawler directives"

    @property
    def permissions(self) -> List[str]:
        return ["network", "active"]

    def _parse_robots_txt(self, content: str) -> Dict[str, Any]:
        """Parse robots.txt content"""
        analysis = {
            "user_agents": [],
            "disallowed_paths": [],
            "allowed_paths": [],
            "sitemaps": [],
            "crawl_delays": {},
            "host_directive": None,
            "has_robots": True,
        }

        lines = content.split('\n')
        current_user_agent = "*"

        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            if line.lower().startswith('user-agent:'):
                current_user_agent = line.split(':', 1)[1].strip()
                if current_user_agent not in analysis["user_agents"]:
                    analysis["user_agents"].append(current_user_agent)
            elif line.lower().startswith('disallow:'):
                path = line.split(':', 1)[1].strip()
                if path:
                    analysis["disallowed_paths"].append({"user_agent": current_user_agent, "path": path})
            elif line.lower().startswith('allow:'):
                path = line.split(':', 1)[1].strip()
                if path:
                    analysis["allowed_paths"].append({"user_agent": current_user_agent, "path": path})
            elif line.lower().startswith('sitemap:'):
                sitemap = line.split(':', 1)[1].strip()
                analysis["sitemaps"].append(sitemap)
            elif line.lower().startswith('crawl-delay:'):
                try:
                    delay = float(line.split(':', 1)[1].strip())
                    analysis["crawl_delays"][current_user_agent] = delay
                except:
                    pass
            elif line.lower().startswith('host:'):
                analysis["host_directive"] = line.split(':', 1)[1].strip()

        return analysis

    async def scan(self, target: str, target_type: str) -> Dict[str, Any]:
        """Perform robots.txt analysis"""
        if target_type not in ["domain", "ip"]:
            return {}

        try:
            # Try different URLs for robots.txt
            urls_to_try = []
            if target_type == "domain":
                urls_to_try = [f"https://{target}/robots.txt", f"http://{target}/robots.txt"]
            else:  # ip
                urls_to_try = [f"https://{target}/robots.txt", f"http://{target}/robots.txt"]

            for url in urls_to_try:
                try:
                    response = await self.network_client.get(url, follow_redirects=True)

                    if response.status_code == 200:
                        content = response.text
                        analysis = self._parse_robots_txt(content)

                        return {
                            "robots_txt": {
                                "url": url,
                                "content": content[:2000],  # Limit content size
                                "analysis": analysis,
                            },
                            "sources": ["robots"],
                            "confidence": 0.9,
                        }
                    elif response.status_code == 404:
                        # No robots.txt found
                        return {
                            "robots_txt": {
                                "url": url,
                                "found": False,
                                "message": "No robots.txt file found",
                            },
                            "sources": ["robots"],
                            "confidence": 0.8,
                        }

                except Exception:
                    continue

            return {"error": "Could not access robots.txt", "sources": ["robots"], "confidence": 0.0}

        except Exception as e:
            return {
                "error": str(e),
                "sources": ["robots"],
                "confidence": 0.0,
            }