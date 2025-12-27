"""DNS module for mangosint"""

import asyncio
import socket
from typing import Any, Dict, List

from mangosint.core.config import Config
from mangosint.core.network import NetworkClient
from mangosint.modules.base import Module


class DNSModule(Module):
    """DNS resolution module"""

    def __init__(self, config: Config, network_client: NetworkClient):
        super().__init__(config, network_client)
        self.network_client = network_client

    @property
    def name(self) -> str:
        return "dns"

    @property
    def description(self) -> str:
        return "DNS resolution and lookup"

    @property
    def permissions(self) -> List[str]:
        return ["network"]

    async def scan(self, target: str, target_type: str) -> Dict[str, Any]:
        """Perform DNS scan"""
        if target_type != "domain":
            return {}

        try:
            # Basic DNS resolution
            ips = await asyncio.get_event_loop().getaddrinfo(
                target, None, family=socket.AF_INET, type=socket.SOCK_STREAM
            )
            ipv4_addresses = list(set(ip[4][0] for ip in ips))

            # IPv6 if enabled
            ipv6_addresses = []
            if self.config.network.ipv6:
                try:
                    ips_v6 = await asyncio.get_event_loop().getaddrinfo(
                        target, None, family=socket.AF_INET6, type=socket.SOCK_STREAM
                    )
                    ipv6_addresses = list(set(ip[4][0] for ip in ips_v6))
                except:
                    pass

            # Create detailed IP objects
            detailed_ips = []
            for ip in ipv4_addresses + ipv6_addresses:
                ip_detail = {
                    "address": ip,
                    "asn": None,
                    "organization": None,
                    "isp": None,
                    "country": None,
                    "city": None,
                    "hostname": None
                }
                detailed_ips.append(ip_detail)

            return {
                "ips": detailed_ips,
                "sources": ["dns"],
                "confidence": 0.9,
            }
        except Exception as e:
            return {
                "error": str(e),
                "sources": ["dns"],
                "confidence": 0.0,
            }