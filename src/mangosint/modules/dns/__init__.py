"""DNS module for mangosint"""

import asyncio
import socket
from typing import Any, Dict, List

from mangosint.core.config import Config
from mangosint.core.network import NetworkClient
from mangosint.modules.base import Module


class DNSModule(Module):
    """DNS resolution and comprehensive record lookup module"""

    def __init__(self, config: Config, network_client: NetworkClient):
        super().__init__(config, network_client)
        self.network_client = network_client

    @property
    def name(self) -> str:
        return "dns"

    @property
    def description(self) -> str:
        return "DNS resolution and comprehensive record lookup"

    @property
    def permissions(self) -> List[str]:
        return ["network"]

    async def _get_dns_records(self, domain: str, record_type: str) -> List[str]:
        """Get DNS records of specified type"""
        try:
            import dns.resolver
            import dns.rdatatype

            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 10

            # Use system DNS (not over proxy for DNS queries)
            answers = resolver.resolve(domain, record_type)
            return [str(rdata) for rdata in answers]
        except ImportError:
            # Fallback if dnspython not available
            return []
        except Exception:
            return []

    async def scan(self, target: str, target_type: str) -> Dict[str, Any]:
        """Perform comprehensive DNS scan"""
        if target_type != "domain":
            return {}

        try:
            result = {
                "dns_records": {},
                "sources": ["dns"],
                "confidence": 0.9,
            }

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

            result["ips"] = detailed_ips

            # Get comprehensive DNS records
            record_types = ["A", "AAAA", "MX", "TXT", "CNAME", "NS", "SOA", "SRV", "PTR"]
            dns_records = {}

            for record_type in record_types:
                try:
                    records = await self._get_dns_records(target, record_type)
                    if records:
                        dns_records[record_type.lower()] = records
                except:
                    continue

            if dns_records:
                result["dns_records"] = dns_records

            # Extract additional intelligence from records
            mx_records = dns_records.get("mx", [])
            if mx_records:
                result["mail_servers"] = mx_records

            txt_records = dns_records.get("txt", [])
            if txt_records:
                # Look for SPF, DMARC, DKIM
                spf_records = [r for r in txt_records if "v=spf1" in r.lower()]
                dmarc_records = [r for r in txt_records if "_dmarc" in target.lower() or "v=DMARC1" in r]
                dkim_records = [r for r in txt_records if any(selector in r.lower() for selector in ["dkim", "selector"])]

                if spf_records:
                    result["spf_records"] = spf_records
                if dmarc_records:
                    result["dmarc_records"] = dmarc_records
                if dkim_records:
                    result["dkim_records"] = dkim_records

            return result

        except Exception as e:
            return {
                "error": str(e),
                "sources": ["dns"],
                "confidence": 0.0,
            }