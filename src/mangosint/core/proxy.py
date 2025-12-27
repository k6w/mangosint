"""Proxy management system"""

import asyncio
import random
import re
from typing import List, Optional, Tuple
from urllib.parse import urlparse

import httpx

from mangosint.core.config import Config


class Proxy:
    """Proxy configuration"""

    def __init__(self, protocol: str, host: str, port: int, username: Optional[str] = None, password: Optional[str] = None):
        self.protocol = protocol
        self.host = host
        self.port = port
        self.username = username
        self.password = password

    @classmethod
    def from_url(cls, url: str) -> "Proxy":
        """Parse proxy from URL"""
        parsed = urlparse(url)
        protocol = parsed.scheme
        host = parsed.hostname
        port = parsed.port
        username = parsed.username
        password = parsed.password

        if not host or not port:
            raise ValueError(f"Invalid proxy URL: {url}")

        return cls(protocol, host, port, username, password)

    def to_url(self) -> str:
        """Convert to URL format"""
        auth = ""
        if self.username:
            auth = f"{self.username}:{self.password}@" if self.password else f"{self.username}@"
        return f"{self.protocol}://{auth}{self.host}:{self.port}"

    def to_httpx_proxy(self) -> Optional[dict]:
        """Convert to httpx proxy format"""
        url = self.to_url()
        if self.protocol in ["http", "https"]:
            return {"http://": url, "https://": url}
        elif self.protocol in ["socks5", "socks4"]:
            # httpx doesn't support SOCKS natively
            return None
        else:
            return {"http://": url, "https://": url}


class ProxyManager:
    """Manages proxy pool and rotation"""

    def __init__(self, config: Config):
        self.config = config
        self.proxies: List[Proxy] = []
        self.validated_proxies: List[Proxy] = []
        self.current_index = 0

    async def fetch_github_proxies(self, repo: str = "proxifly/free-proxy-list") -> List[str]:
        """Fetch proxies from GitHub repository"""
        # Direct URL to the proxy list file
        url = "https://raw.githubusercontent.com/proxifly/free-proxy-list/refs/heads/main/proxies/all/data.txt"

        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(url)
                response.raise_for_status()
                content = response.text

                proxy_urls = []
                # Parse proxy URLs from content
                lines = content.split("\n")
                for line in lines:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        proxy_urls.append(line)

                return proxy_urls

            except Exception as e:
                print(f"Error fetching proxies from GitHub: {e}")
                return []

    async def validate_proxy(self, proxy: Proxy, timeout: int = 3) -> bool:
        """Validate proxy by testing connection"""
        try:
            if proxy.protocol in ["socks5", "socks4"]:
                # For SOCKS proxies, just test basic connectivity to the proxy server
                import socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((proxy.host, proxy.port))
                sock.close()
                return result == 0
            else:
                # For HTTP/HTTPS proxies, test with a simple HEAD request to a reliable site
                async with httpx.AsyncClient(proxies=proxy.to_httpx_proxy(), timeout=timeout) as client:
                    response = await client.head("https://httpbin.org/status/200")
                    return response.status_code == 200
        except:
            return False

    async def load_and_validate_proxies(self) -> None:
        """Load proxies from sources and validate them"""
        all_proxy_urls = []

        for source in self.config.proxy_pool.sources:
            if source.startswith("github:"):
                repo = source.split(":", 1)[1]
                urls = await self.fetch_github_proxies(repo)
                all_proxy_urls.extend(urls)
            elif source.startswith("local:"):
                # TODO: Load from local file
                pass

        # Parse and deduplicate - only keep SOCKS proxies for faster validation
        seen = set()
        proxies = []
        for url in all_proxy_urls:
            if url not in seen and (url.startswith("socks4://") or url.startswith("socks5://")):
                try:
                    proxy = Proxy.from_url(url)
                    proxies.append(proxy)
                    seen.add(url)
                except:
                    continue

        # Validate proxies (limit to first 5 for speed)
        validated = []
        semaphore = asyncio.Semaphore(3)  # Limit concurrent validations

        async def validate_with_semaphore(proxy):
            async with semaphore:
                if await self.validate_proxy(proxy, timeout=1):  # Very short timeout
                    return proxy
            return None

        tasks = [validate_with_semaphore(proxy) for proxy in proxies[:5]]  # Only validate first 5
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Proxy):
                validated.append(result)

        self.validated_proxies = validated
        print(f"Loaded and validated {len(validated)} proxies")

    def get_proxy(self) -> Optional[Proxy]:
        """Get next proxy from pool"""
        if not self.validated_proxies:
            return None

        if self.config.proxy_pool.rotation == "per-request":
            proxy = random.choice(self.validated_proxies)
        else:
            proxy = self.validated_proxies[self.current_index % len(self.validated_proxies)]
            self.current_index += 1

        return proxy

    def get_current_proxy(self) -> Optional[Proxy]:
        """Get the configured proxy"""
        if self.config.proxy.host:
            return Proxy(
                self.config.proxy.type,
                self.config.proxy.host,
                self.config.proxy.port
            )
        return None