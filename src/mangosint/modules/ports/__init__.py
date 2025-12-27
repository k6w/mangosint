"""Port scanning module for mangosint"""

import asyncio
import socket
from typing import Any, Dict, List

from mangosint.core.config import Config
from mangosint.core.network import NetworkClient
from mangosint.modules.base import Module


class PortScanModule(Module):
    """Port scanning module"""

    def __init__(self, config: Config, network_client: NetworkClient):
        super().__init__(config, network_client)
        # Comprehensive port list with common services
        self.tcp_ports = [
            21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 111, 123, 135, 139, 143, 161, 162,
            389, 443, 445, 465, 514, 587, 631, 636, 993, 995, 1080, 1194, 1433, 1521,
            2049, 2082, 2083, 2086, 2087, 2095, 2096, 2222, 2375, 2376, 3128, 3306,
            3389, 5432, 5900, 5985, 5986, 6379, 6667, 6697, 6881, 6969, 8080, 8081,
            8443, 8888, 9000, 9090, 9200, 9300, 9418, 9999, 11211, 27017, 27018, 27019
        ]
        # Blacklist domains that are official services and shouldn't be scanned
        self.blacklist_domains = {
            'google.com', 'www.google.com', 'youtube.com', 'facebook.com', 'amazon.com',
            'microsoft.com', 'apple.com', 'cloudflare.com', 'akamai.com', 'fastly.com',
            'github.com', 'gitlab.com', 'bitbucket.org', 'twitter.com', 'instagram.com',
            'linkedin.com', 'netflix.com', 'spotify.com', 'discord.com', 'slack.com',
            'zoom.us', 'teams.microsoft.com', 'dropbox.com', 'box.com', 'onedrive.com'
        }

    @property
    def name(self) -> str:
        return "ports"

    @property
    def description(self) -> str:
        return "Port scanning and service detection"

    @property
    def permissions(self) -> List[str]:
        return ["network", "active"]

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private"""
        import ipaddress
        try:
            addr = ipaddress.ip_address(ip)
            return addr.is_private
        except:
            return False

    def _is_blacklisted_domain(self, domain: str) -> bool:
        """Check if domain is in blacklist"""
        domain_lower = domain.lower()
        return domain_lower in self.blacklist_domains or any(domain_lower.endswith('.' + d) for d in self.blacklist_domains)

    async def _grab_banner(self, reader, writer, port: int, ip: str) -> tuple[str, str]:
        """Grab service banner and detect protocol"""
        try:
            if port in [21]:  # FTP
                banner = await asyncio.wait_for(reader.read(1024), timeout=1.0)
                banner_text = banner.decode('utf-8', errors='ignore').strip()
                if '220' in banner_text:
                    return 'ftp', banner_text
            elif port in [22]:  # SSH
                banner = await asyncio.wait_for(reader.read(1024), timeout=1.0)
                banner_text = banner.decode('utf-8', errors='ignore').strip()
                if 'SSH' in banner_text:
                    version = banner_text.split('SSH-')[1].split()[0] if 'SSH-' in banner_text else 'unknown'
                    return f'ssh-{version}', banner_text
            elif port in [23]:  # Telnet
                banner = await asyncio.wait_for(reader.read(1024), timeout=1.0)
                banner_text = banner.decode('utf-8', errors='ignore').strip()
                return 'telnet', banner_text
            elif port in [25, 465, 587]:  # SMTP
                banner = await asyncio.wait_for(reader.read(1024), timeout=1.0)
                banner_text = banner.decode('utf-8', errors='ignore').strip()
                if '220' in banner_text:
                    return 'smtp', banner_text
            elif port in [53]:  # DNS (TCP)
                # Send DNS query
                import struct
                query = b'\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x06google\x03com\x00\x00\x01\x00\x01'
                writer.write(query)
                await writer.drain()
                response = await asyncio.wait_for(reader.read(1024), timeout=1.0)
                if len(response) > 12:
                    return 'dns', 'DNS service detected'
            elif port in [80, 8080, 8081, 8888, 9000]:  # HTTP
                request = f"GET / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n".encode()
                writer.write(request)
                await writer.drain()
                response = await asyncio.wait_for(reader.read(2048), timeout=2.0)
                response_text = response.decode('utf-8', errors='ignore')
                if 'HTTP/' in response_text:
                    # Extract server info
                    server_line = ''
                    for line in response_text.split('\n'):
                        if line.lower().startswith('server:'):
                            server_line = line.split(':', 1)[1].strip()
                            break
                    return f'http ({server_line})' if server_line else 'http', response_text[:200]
            elif port in [110, 995]:  # POP3
                banner = await asyncio.wait_for(reader.read(1024), timeout=1.0)
                banner_text = banner.decode('utf-8', errors='ignore').strip()
                if banner_text.startswith('+OK'):
                    return 'pop3', banner_text
            elif port in [135]:  # RPC
                return 'rpc', 'Microsoft RPC detected'
            elif port in [139, 445]:  # NetBIOS/SMB
                return 'smb', 'SMB/CIFS service detected'
            elif port in [143, 993]:  # IMAP
                banner = await asyncio.wait_for(reader.read(1024), timeout=1.0)
                banner_text = banner.decode('utf-8', errors='ignore').strip()
                if banner_text.startswith('* OK'):
                    return 'imap', banner_text
            elif port in [161, 162]:  # SNMP
                # Send SNMP GET request (community: public)
                snmp_get = b'\x30\x26\x02\x01\x00\x04\x06\x70\x75\x62\x6c\x69\x63\xa0\x19\x02\x04\x00\x00\x00\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x01\x01\x05\x00'
                writer.write(snmp_get)
                await writer.drain()
                response = await asyncio.wait_for(reader.read(1024), timeout=1.0)
                if response.startswith(b'\x30'):
                    return 'snmp', 'SNMP service detected'
            elif port in [389]:  # LDAP
                return 'ldap', 'LDAP service detected'
            elif port in [443, 8443]:  # HTTPS
                # Try SSL handshake
                try:
                    import ssl
                    ssl_context = ssl.create_default_context()
                    ssl_context.check_hostname = False
                    ssl_context.verify_mode = ssl.CERT_NONE
                    
                    # Create SSL connection
                    loop = asyncio.get_event_loop()
                    ssl_reader, ssl_writer = await asyncio.wait_for(
                        asyncio.open_connection(ip, port, ssl=ssl_context), timeout=3.0
                    )
                    
                    # Send HTTP request over SSL
                    request = f"GET / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n".encode()
                    ssl_writer.write(request)
                    await ssl_writer.drain()
                    response = await asyncio.wait_for(ssl_reader.read(2048), timeout=2.0)
                    response_text = response.decode('utf-8', errors='ignore')
                    
                    ssl_writer.close()
                    await ssl_writer.wait_closed()
                    
                    if 'HTTP/' in response_text:
                        server_line = ''
                        for line in response_text.split('\n'):
                            if line.lower().startswith('server:'):
                                server_line = line.split(':', 1)[1].strip()
                                break
                        return f'https ({server_line})' if server_line else 'https', response_text[:200]
                except:
                    pass
                
                # Fallback to regular HTTP check
                request = f"GET / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n".encode()
                writer.write(request)
                await writer.drain()
                response = await asyncio.wait_for(reader.read(2048), timeout=2.0)
                response_text = response.decode('utf-8', errors='ignore')
                if 'HTTP/' in response_text:
                    return 'https', response_text[:200]
            elif port in [636]:  # LDAPS
                return 'ldaps', 'LDAP over SSL detected'
            elif port in [1080]:  # SOCKS
                return 'socks', 'SOCKS proxy detected'
            elif port in [1194]:  # OpenVPN
                return 'openvpn', 'OpenVPN detected'
            elif port in [1433]:  # MSSQL
                return 'mssql', 'Microsoft SQL Server detected'
            elif port in [1521]:  # Oracle
                return 'oracle', 'Oracle Database detected'
            elif port in [2049]:  # NFS
                return 'nfs', 'NFS detected'
            elif port in [2082, 2083, 2086, 2087, 2095, 2096]:  # cPanel
                request = f"GET / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n".encode()
                writer.write(request)
                await writer.drain()
                response = await asyncio.wait_for(reader.read(2048), timeout=2.0)
                response_text = response.decode('utf-8', errors='ignore')
                if 'HTTP/' in response_text and ('cpanel' in response_text.lower() or 'whm' in response_text.lower()):
                    return 'cpanel', response_text[:200]
            elif port in [2222]:  # DirectAdmin
                return 'directadmin', 'DirectAdmin detected'
            elif port in [2375, 2376]:  # Docker
                request = b"GET /_ping HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
                writer.write(request)
                await writer.drain()
                response = await asyncio.wait_for(reader.read(1024), timeout=1.0)
                if b'OK' in response:
                    return 'docker', 'Docker API detected'
            elif port in [3128]:  # Squid
                return 'squid', 'Squid proxy detected'
            elif port in [3306]:  # MySQL
                return 'mysql', 'MySQL detected'
            elif port in [3389]:  # RDP
                return 'rdp', 'Remote Desktop Protocol detected'
            elif port in [5432]:  # PostgreSQL
                return 'postgresql', 'PostgreSQL detected'
            elif port in [5900]:  # VNC
                return 'vnc', 'VNC detected'
            elif port in [5985, 5986]:  # WinRM
                return 'winrm', 'Windows Remote Management detected'
            elif port in [6379]:  # Redis
                return 'redis', 'Redis detected'
            elif port in [6667, 6697]:  # IRC
                return 'irc', 'IRC detected'
            elif port in [6881, 6969]:  # BitTorrent
                return 'bittorrent', 'BitTorrent detected'
            elif port in [9090]:  # Prometheus
                return 'prometheus', 'Prometheus detected'
            elif port in [9200, 9300]:  # Elasticsearch
                request = b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
                writer.write(request)
                await writer.drain()
                response = await asyncio.wait_for(reader.read(1024), timeout=1.0)
                response_text = response.decode('utf-8', errors='ignore')
                if 'elasticsearch' in response_text.lower():
                    return 'elasticsearch', response_text[:200]
            elif port in [9418]:  # Git
                return 'git', 'Git daemon detected'
            elif port in [9999]:  # Urchin
                return 'urchin', 'Urchin web analytics detected'
            elif port in [11211]:  # Memcached
                return 'memcached', 'Memcached detected'
            elif port in [27017, 27018, 27019]:  # MongoDB
                return 'mongodb', 'MongoDB detected'
                
        except Exception as e:
            pass
        
        return 'unknown', ''

    async def scan(self, target: str, target_type: str) -> Dict[str, Any]:
        """Perform port scan"""
        if target_type not in ["ip", "domain", "ip_port"]:
            return {}

        # Check for blacklisted domains
        if target_type == "domain" and self._is_blacklisted_domain(target):
            return {
                "error": f"Scanning of official service domains like {target} is not allowed",
                "sources": ["ports"],
                "module": "ports",
                "confidence": 0.0
            }

        # Extract IP
        if target_type == "ip_port":
            ip = target.split(":")[0]
        elif target_type == "domain":
            # Resolve domain to IP first
            try:
                loop = asyncio.get_event_loop()
                result = await loop.getaddrinfo(target, None, family=socket.AF_INET, type=socket.SOCK_STREAM)
                if result:
                    ip = result[0][4][0]
                else:
                    return {"error": "Could not resolve domain", "sources": ["ports"], "module": "ports", "confidence": 0.0}
            except:
                return {"error": "DNS resolution failed", "sources": ["ports"], "module": "ports", "confidence": 0.0}
        else:
            ip = target

        # Check for private IPs
        if self._is_private_ip(ip):
            return {
                "error": "Scanning of private IP addresses is not allowed",
                "sources": ["ports"],
                "module": "ports",
                "confidence": 0.0
            }

        # Perform real port scanning
        open_ports = []
        services = {}
        service_banners = {}

        # Scan TCP ports (limit to 50 ports for performance)
        for port in self.tcp_ports[:50]:
            try:
                # Try to connect
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port),
                    timeout=2.0
                )

                open_ports.append(port)

                # Grab banner and detect service
                service_name, banner = await self._grab_banner(reader, writer, port, ip)
                services[port] = service_name
                if banner:
                    service_banners[port] = banner[:500]  # Limit banner size

                writer.close()
                await writer.wait_closed()

            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                continue

        # Prepare result
        result = {
            "ports": open_ports,
            "services": services,
            "sources": ["ports"],
            "confidence": 0.9 if open_ports else 0.5,
        }
        
        # Add banners if any were captured
        if service_banners:
            result["service_banners"] = service_banners

        return result