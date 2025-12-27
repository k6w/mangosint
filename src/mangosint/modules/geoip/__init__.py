"""IP Geolocation module for mangosint"""

import json
from typing import Any, Dict, List

from mangosint.core.config import Config
from mangosint.core.network import NetworkClient
from mangosint.modules.base import Module


class IPGeolocationModule(Module):
    """IP geolocation module using free services"""

    def __init__(self, config: Config, network_client: NetworkClient):
        super().__init__(config, network_client)

    @property
    def name(self) -> str:
        return "geoip"

    @property
    def description(self) -> str:
        return "IP geolocation and location intelligence"

    @property
    def permissions(self) -> List[str]:
        return ["network"]

    async def _get_ipinfo_geolocation(self, ip: str) -> Dict[str, Any]:
        """Get geolocation from ipinfo.io (free tier)"""
        try:
            response = await self.network_client.get(f"https://ipinfo.io/{ip}/json")
            if response.status_code == 200:
                data = response.json()
                return {
                    "country": data.get("country"),
                    "region": data.get("region"),
                    "city": data.get("city"),
                    "postal": data.get("postal"),
                    "timezone": data.get("timezone"),
                    "org": data.get("org"),
                    "hostname": data.get("hostname"),
                }
        except:
            pass
        return {}

    async def _get_ipapi_geolocation(self, ip: str) -> Dict[str, Any]:
        """Get geolocation from ip-api.com (free)"""
        try:
            response = await self.network_client.get(f"http://ip-api.com/json/{ip}")
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "success":
                    return {
                        "country": data.get("countryCode"),
                        "region": data.get("regionName"),
                        "city": data.get("city"),
                        "postal": data.get("zip"),
                        "timezone": data.get("timezone"),
                        "org": data.get("org"),
                        "isp": data.get("isp"),
                        "as": data.get("as"),
                    }
        except:
            pass
        return {}

    async def scan(self, target: str, target_type: str) -> Dict[str, Any]:
        """Perform IP geolocation"""
        if target_type not in ["ip", "domain"]:
            return {}

        try:
            # Get IPs to geolocate
            ips_to_check = []

            if target_type == "ip":
                ips_to_check = [target]
            elif target_type == "domain":
                # This module processes IPs, not domains directly
                return {}

            result = {
                "geolocation": {},
                "sources": ["geoip"],
                "confidence": 0.7,
            }

            # Perform geolocation for each IP
            for ip in ips_to_check:
                geo_data = {}

                # Try multiple free services
                ipinfo_data = await self._get_ipinfo_geolocation(ip)
                ipapi_data = await self._get_ipapi_geolocation(ip)

                # Merge data from multiple sources
                geo_data.update(ipinfo_data)
                geo_data.update(ipapi_data)  # ip-api data takes precedence for conflicts

                if geo_data:
                    result["geolocation"][ip] = geo_data

            if result["geolocation"]:
                return result
            else:
                return {"error": "No geolocation data found", "sources": ["geoip"], "confidence": 0.0}

        except Exception as e:
            return {
                "error": str(e),
                "sources": ["geoip"],
                "confidence": 0.0,
            }