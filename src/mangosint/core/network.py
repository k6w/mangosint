"""Proxy-enforced network layer"""

import asyncio
import random
import time
from typing import Any, Dict, Optional

import httpx

from mangosint.core.config import Config
from mangosint.core.proxy import ProxyManager


class NetworkClient:
    """Network client with mandatory proxy enforcement"""

    def __init__(self, config: Config):
        self.config = config
        self.proxy_manager = ProxyManager(config)
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        ]
        self.last_request_time = 0
        self.min_delay = 1.0  # Minimum delay between requests

    async def initialize(self):
        """Initialize proxy pool"""
        if self.config.proxy_pool.enabled:
            await self.proxy_manager.load_and_validate_proxies()

    def _get_proxy_config(self) -> Optional[Dict[str, str]]:
        """Get proxy configuration for httpx"""
        if self.config.network.mode == "offline":
            raise RuntimeError("Network operations disabled in offline mode")

        proxy = None
        if self.config.proxy_pool.enabled and self.proxy_manager.validated_proxies:
            proxy = self.proxy_manager.get_proxy()
        else:
            proxy = self.proxy_manager.get_current_proxy()

        if not proxy:
            if self.config.network.force_proxy:
                raise RuntimeError("No proxy available but proxy is required")
            return None

        httpx_proxy = proxy.to_httpx_proxy()
        return httpx_proxy

    def _get_headers(self) -> Dict[str, str]:
        """Get request headers with rotated user agent"""
        return {
            "User-Agent": random.choice(self.user_agents),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "DNT": "1",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }

    async def _rate_limit(self):
        """Apply rate limiting"""
        elapsed = time.time() - self.last_request_time
        if elapsed < self.min_delay:
            jitter = random.uniform(0.1, 0.5)
            await asyncio.sleep(self.min_delay - elapsed + jitter)
        self.last_request_time = time.time()

    async def get(self, url: str, **kwargs) -> httpx.Response:
        """Make GET request with proxy enforcement"""
        await self._rate_limit()

        proxy_config = self._get_proxy_config()
        headers = self._get_headers()

        client_kwargs = {
            "headers": headers,
            "timeout": 30,
            "follow_redirects": True
        }
        
        if proxy_config:
            client_kwargs["proxies"] = proxy_config

        async with httpx.AsyncClient(**client_kwargs) as client:
            response = await client.get(url, **kwargs)
            return response

    async def post(self, url: str, data: Any = None, json: Any = None, **kwargs) -> httpx.Response:
        """Make POST request with proxy enforcement"""
        await self._rate_limit()

        proxy_config = self._get_proxy_config()
        headers = self._get_headers()

        client_kwargs = {
            "headers": headers,
            "timeout": 30,
            "follow_redirects": True
        }
        
        if proxy_config:
            client_kwargs["proxies"] = proxy_config

        async with httpx.AsyncClient(**client_kwargs) as client:
            response = await client.post(url, data=data, json=json, **kwargs)
            return response

    async def resolve_dns(self, hostname: str) -> Optional[str]:
        """Resolve DNS through proxy if configured"""
        if self.config.network.dns_over_proxy:
            # For DNS over proxy, we'd need to implement custom DNS resolution
            # For now, use system DNS but warn
            pass

        # Use asyncio.getaddrinfo for DNS resolution
        try:
            loop = asyncio.get_event_loop()
            result = await loop.getaddrinfo(hostname, None, family=0, type=0)
            # Return first IPv4 address
            for family, type, proto, canonname, sockaddr in result:
                if family == 2:  # IPv4
                    return sockaddr[0]
        except:
            return None

        return None