"""Reverse DNS module for mangosint"""

import asyncio
import socket
from typing import Any, Dict, List

from mangosint.core.config import Config
from mangosint.core.network import NetworkClient
from mangosint.modules.base import Module


class ReverseDNSModule(Module):
    """Reverse DNS (PTR) lookup module"""

    def __init__(self, config: Config, network_client: NetworkClient):
        super().__init__(config, network_client)

    @property
    def name(self) -> str:
        return "rdns"

    @property
    def description(self) -> str:
        return "Reverse DNS (PTR) record lookup"

    @property
    def permissions(self) -> List[str]:
        return ["network"]

    async def _reverse_lookup(self, ip: str) -> str:
        """Perform reverse DNS lookup for an IP"""
        try:
            loop = asyncio.get_event_loop()
            result = await loop.getnameinfo((ip, 0), socket.NI_NAMEREQD)
            return result[0]  # hostname
        except:
            return None

    async def scan(self, target: str, target_type: str) -> Dict[str, Any]:
        """Perform reverse DNS scan"""
        if target_type not in ["ip", "domain"]:
            return {}

        try:
            result = {
                "reverse_dns": {},
                "sources": ["rdns"],
                "confidence": 0.8,
            }

            # Get IPs to reverse lookup
            ips_to_check = []

            if target_type == "ip":
                ips_to_check = [target]
            elif target_type == "domain":
                # Resolve domain to IPs first
                try:
                    ips = await asyncio.get_event_loop().getaddrinfo(
                        target, None, family=socket.AF_INET, type=socket.SOCK_STREAM
                    )
                    ipv4_addresses = list(set(ip[4][0] for ip in ips))
                    ips_to_check = ipv4_addresses[:5]  # Limit to 5 IPs
                except:
                    return {"error": "Could not resolve domain", "sources": ["rdns"], "confidence": 0.0}

            # Perform reverse lookups
            reverse_lookups = {}
            for ip in ips_to_check:
                hostname = await self._reverse_lookup(ip)
                if hostname:
                    reverse_lookups[ip] = hostname

            if reverse_lookups:
                result["reverse_dns"] = reverse_lookups

            return result

        except Exception as e:
            return {
                "error": str(e),
                "sources": ["rdns"],
                "confidence": 0.0,
            }