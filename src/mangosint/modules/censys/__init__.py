"""Censys module for mangosint"""

import asyncio
from typing import Any, Dict, List

from mangosint.core.config import Config
from mangosint.core.network import NetworkClient
from mangosint.modules.base import Module


class CensysModule(Module):
    """Censys internet scanner module"""

    def __init__(self, config: Config, network_client: NetworkClient):
        super().__init__(config, network_client)
        self.api_key = config.api.censys_api_key

    @property
    def name(self) -> str:
        return "censys"

    @property
    def description(self) -> str:
        return "Censys internet-wide scanning data"

    @property
    def permissions(self) -> List[str]:
        return ["network", "api"]

    async def scan(self, target: str, target_type: str) -> Dict[str, Any]:
        """Perform Censys scan using platform API lookups (credit-efficient)"""
        if not self.api_key:
            return {"error": "Censys Personal Access Token not configured", "sources": ["censys"], "module": "censys", "confidence": 0.0}

        try:
            # Import here to avoid dependency issues if not installed
            from censys_platform import SDK

            # Use asyncio to run the sync SDK in a thread
            def _censys_lookup():
                try:
                    # Use httpx directly since the SDK methods seem broken
                    import httpx
                    
                    headers = {
                        'Authorization': f'Bearer {self.api_key}',
                        'Accept': 'application/vnd.censys.api.v3.host.v1+json'
                    }
                    
                    with httpx.Client() as client:
                        if target_type == "ip":
                            # Host lookup - 1 credit for free users
                            url = f"https://api.platform.censys.io/v3/global/asset/host/{target}"
                            response = client.get(url, headers=headers)
                            if response.status_code == 200:
                                return {"type": "host", "data": response.json()}
                            else:
                                return {"error": f"HTTP {response.status_code}: {response.text}"}
                        elif target_type == "domain":
                            # Web property lookup - 1 credit for free users
                            headers['Accept'] = 'application/vnd.censys.api.v3.web_property.v1+json'
                            url = f"https://api.platform.censys.io/v3/global/asset/web-property/{target}"
                            response = client.get(url, headers=headers)
                            if response.status_code == 200:
                                return {"type": "web_property", "data": response.json()}
                            else:
                                return {"error": f"HTTP {response.status_code}: {response.text}"}
                        else:
                            # Fallback to search for other types - requires paid plan
                            headers['Accept'] = 'application/vnd.censys.api.v3.global.v1+json'
                            url = "https://api.platform.censys.io/v3/global/data/search"
                            payload = {
                                "fields": [
                                    "host.ip",
                                    "host.services.port",
                                    "host.services.service_name",
                                    "host.services.transport_protocol",
                                    "host.services.http.response.headers.server",
                                ],
                                "page_size": 5,
                                "query": target,
                            }
                            response = client.post(url, headers=headers, json=payload)
                            if response.status_code == 200:
                                return {"type": "search", "data": response.json()}
                            else:
                                return {"error": f"HTTP {response.status_code}: {response.text}"}
                except Exception as e:
                    return {"error": str(e)}

            # Run in thread pool to avoid blocking
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(None, _censys_lookup)

            # Check if we got an error
            if isinstance(result, dict) and "error" in result:
                error_msg = result["error"]
                # Provide user-friendly error messages for common API issues
                if "organization ID" in error_msg or "Forbidden" in error_msg:
                    if target_type == "domain":
                        friendly_error = "Censys domain/web property searches require a paid plan or organization access. Free users can only perform IP lookups (1 credit each)."
                    else:
                        friendly_error = "Censys API access requires a paid plan or organization access for this operation."
                elif "404" in error_msg:
                    if target_type == "domain":
                        friendly_error = "Censys web property lookup is not available or the domain has no data. Try using a paid plan for full access."
                    else:
                        friendly_error = f"Censys API Error: {error_msg}"
                else:
                    friendly_error = f"Censys API Error: {error_msg}"
                
                return {
                    "error": friendly_error,
                    "sources": ["censys"],
                    "module": "censys",
                    "confidence": 0.0
                }

            # Process results based on type
            data = result["data"]
            lookup_type = result["type"]

            ips = []
            ports = []
            services = {}
            technologies = []
            subdomains = []

            if lookup_type == "host":
                # Process host data - direct JSON response
                host_data = data.get('result', data)  # API might wrap in 'result'
                # Extract IP
                if 'ip' in host_data:
                    ips.append(host_data['ip'])

                # Extract services and ports
                if 'services' in host_data:
                    for service in host_data['services']:
                        # Port information
                        if 'port' in service:
                            port = service['port']
                            if port not in ports:
                                ports.append(port)

                        # Service information
                        service_name = service.get('service_name', 'unknown')
                        transport = service.get('transport_protocol', 'tcp')
                        port_num = service.get('port', 0)

                        if port_num not in services:
                            services[port_num] = []

                        service_info = f"{service_name}/{transport}"
                        if service_info not in services[port_num]:
                            services[port_num].append(service_info)

                        # Extract technologies from HTTP headers
                        if 'http' in service and 'response' in service['http'] and 'headers' in service['http']['response']:
                            headers = service['http']['response']['headers']
                            if 'server' in headers:
                                server = headers['server']
                                if server not in technologies:
                                    technologies.append(server)

            elif lookup_type == "web_property":
                # Process web property data - direct JSON response
                wp_data = data.get('result', data)
                # Extract domain/IP information
                if 'domain' in wp_data:
                    # This might give us the main domain, but not necessarily IPs
                    pass
                
                # Web properties might have associated hosts
                if 'hosts' in wp_data:
                    for host in wp_data['hosts']:
                        if 'ip' in host:
                            ips.append(host['ip'])

            elif lookup_type == "search":
                # Process search results - direct JSON response
                if 'hits' in data:
                    for hit in data['hits']:
                        # Extract IP
                        if 'host' in hit and 'ip' in hit['host']:
                            ip = hit['host']['ip']
                            if ip not in ips:
                                ips.append(ip)

                        # Extract services and ports
                        if 'host' in hit and 'services' in hit['host']:
                            for service in hit['host']['services']:
                                # Port information
                                if 'port' in service:
                                    port = service['port']
                                    if port not in ports:
                                        ports.append(port)

                                # Service information
                                service_name = service.get('service_name', 'unknown')
                                transport = service.get('transport_protocol', 'tcp')
                                port_num = service.get('port', 0)

                                if port_num not in services:
                                    services[port_num] = []

                                service_info = f"{service_name}/{transport}"
                                if service_info not in services[port_num]:
                                    services[port_num].append(service_info)

                                # Extract technologies from HTTP headers
                                if 'http' in service and 'response' in service['http'] and 'headers' in service['http']['response']:
                                    headers = service['http']['response']['headers']
                                    if 'server' in headers:
                                        server = headers['server']
                                        if server not in technologies:
                                            technologies.append(server)

            return {
                "ips": ips,
                "ports": ports,
                "services": services,
                "technologies": technologies,
                "subdomains": subdomains,
                "sources": ["censys"],
                "confidence": 0.8,
            }

        except Exception as e:
            return {"error": f"Censys API error: {str(e)}", "sources": ["censys"], "module": "censys", "confidence": 0.0}