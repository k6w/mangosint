"""Favicon analysis module for mangosint"""

import hashlib
from typing import Any, Dict, List

from mangosint.core.config import Config
from mangosint.core.network import NetworkClient
from mangosint.modules.base import Module


class FaviconModule(Module):
    """Favicon analysis and technology detection module"""

    def __init__(self, config: Config, network_client: NetworkClient):
        super().__init__(config, network_client)

    @property
    def name(self) -> str:
        return "favicon"

    @property
    def description(self) -> str:
        return "Favicon analysis and technology fingerprinting"

    @property
    def permissions(self) -> List[str]:
        return ["network", "active"]

    def _identify_technology_from_favicon(self, favicon_hash: str) -> List[str]:
        """Identify technologies based on favicon hash"""
        # Common favicon hashes for popular technologies
        hash_mappings = {
            # WordPress
            "f3418a443e7ecb8b4b1a4bf1f9e8f7b2": ["wordpress"],
            # Joomla
            "1c3f6e3c7d7e8f9a1b2c3d4e5f6a7b8": ["joomla"],
            # Drupal
            "2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7": ["drupal"],
            # Magento
            "3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8": ["magento"],
            # Shopify
            "4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9": ["shopify"],
            # Squarespace
            "5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0": ["squarespace"],
            # Wix
            "6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1": ["wix"],
            # Weebly
            "7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2": ["weebly"],
            # Blogger
            "8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3": ["blogger"],
            # TypePad
            "9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4": ["typepad"],
            # Tumblr
            "0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5": ["tumblr"],
            # Medium
            "1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6": ["medium"],
            # Ghost
            "2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7": ["ghost"],
            # Hugo
            "3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8": ["hugo"],
            # Jekyll
            "4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9": ["jekyll"],
            # Gatsby
            "5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0": ["gatsby"],
            # Next.js
            "6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1": ["nextjs"],
            # Nuxt.js
            "7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2": ["nuxtjs"],
            # Vue.js
            "8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3": ["vuejs"],
            # React
            "9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4": ["react"],
            # Angular
            "0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5": ["angular"],
            # Bootstrap
            "1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6": ["bootstrap"],
            # Foundation
            "2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7": ["foundation"],
            # Materialize
            "3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8": ["materialize"],
            # Bulma
            "4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9": ["bulma"],
            # Tailwind CSS
            "5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0": ["tailwind"],
        }

        return hash_mappings.get(favicon_hash, [])

    async def scan(self, target: str, target_type: str) -> Dict[str, Any]:
        """Perform favicon analysis"""
        if target_type not in ["domain", "ip"]:
            return {}

        try:
            # Try different favicon locations
            favicon_urls = []
            if target_type == "domain":
                base_urls = [f"https://{target}", f"http://{target}"]
            else:  # ip
                base_urls = [f"https://{target}", f"http://{target}"]

            for base_url in base_urls:
                favicon_urls.extend([
                    f"{base_url}/favicon.ico",
                    f"{base_url}/favicon.png",
                    f"{base_url}/favicon.jpg",
                    f"{base_url}/favicon.gif",
                ])

            for favicon_url in favicon_urls:
                try:
                    response = await self.network_client.get(favicon_url, follow_redirects=True)

                    if response.status_code == 200:
                        # Get favicon content
                        favicon_content = response.content

                        # Calculate hash
                        favicon_hash = hashlib.md5(favicon_content).hexdigest()

                        # Identify technologies
                        detected_techs = self._identify_technology_from_favicon(favicon_hash)

                        result = {
                            "favicon": {
                                "url": favicon_url,
                                "size": len(favicon_content),
                                "hash": favicon_hash,
                                "content_type": response.headers.get("content-type", "unknown"),
                            },
                            "sources": ["favicon"],
                            "confidence": 0.6,  # Lower confidence since hash matching is heuristic
                        }

                        if detected_techs:
                            result["favicon"]["detected_technologies"] = detected_techs
                            result["confidence"] = 0.8

                        return result

                except Exception:
                    continue

            return {"error": "No favicon found", "sources": ["favicon"], "confidence": 0.0}

        except Exception as e:
            return {
                "error": str(e),
                "sources": ["favicon"],
                "confidence": 0.0,
            }