"""Configuration management for mangosint"""

import json
from pathlib import Path
from typing import List, Optional

from pydantic import BaseModel, Field


class NetworkConfig(BaseModel):
    """Network configuration"""
    mode: str = Field(default="passive", description="Network mode")
    force_proxy: bool = Field(default=True, description="Force proxy usage")
    dns_over_proxy: bool = Field(default=True, description="DNS over proxy")
    ipv6: bool = Field(default=False, description="Enable IPv6")


class ProxyConfig(BaseModel):
    """Proxy configuration"""
    type: str = Field(default="socks5", description="Proxy type")
    host: str = Field(default="127.0.0.1", description="Proxy host")
    port: int = Field(default=9050, description="Proxy port")


class ProxyPoolConfig(BaseModel):
    """Proxy pool configuration"""
    enabled: bool = Field(default=True, description="Enable proxy pool")
    rotation: str = Field(default="per-request", description="Rotation strategy")
    sources: List[str] = Field(default_factory=lambda: ["github:proxifly"], description="Proxy sources")


class APIConfig(BaseModel):
    """API configuration for various services"""
    censys_api_key: Optional[str] = Field(default=None, description="Censys Personal Access Token")
    shodan_api_key: Optional[str] = Field(default=None, description="Shodan API Key")
    virustotal_api_key: Optional[str] = Field(default=None, description="VirusTotal API Key")
    alienvault_api_key: Optional[str] = Field(default=None, description="AlienVault OTX API Key")
    certspotter_api_key: Optional[str] = Field(default=None, description="CertSpotter API Key")
    sslmate_api_key: Optional[str] = Field(default=None, description="SSLMate API Key")
    urlscan_api_key: Optional[str] = Field(default=None, description="URLScan.io API Key")
    hunter_api_key: Optional[str] = Field(default=None, description="Hunter.io API Key")
    hibp_api_key: Optional[str] = Field(default=None, description="HaveIBeenPwned API Key")
    greynoise_api_key: Optional[str] = Field(default=None, description="GreyNoise API Key")


class Config(BaseModel):
    """Main configuration"""
    network: NetworkConfig = Field(default_factory=NetworkConfig)
    proxy: ProxyConfig = Field(default_factory=ProxyConfig)
    proxy_pool: ProxyPoolConfig = Field(default_factory=ProxyPoolConfig)
    api: APIConfig = Field(default_factory=APIConfig)
    threads: int = Field(default=10, description="Default number of threads")

    @classmethod
    def load(cls, config_file: Optional[str] = None) -> "Config":
        """Load configuration from file"""
        if config_file:
            path = Path(config_file)
        else:
            path = Path.home() / ".mangosint" / "config.json"

        if path.exists():
            with open(path, "r") as f:
                data = json.load(f)
            return cls(**data)
        else:
            # Return default config
            return cls()

    def save(self, config_file: Optional[str] = None) -> None:
        """Save configuration to file"""
        if config_file:
            path = Path(config_file)
        else:
            path = Path.home() / ".mangosint" / "config.json"

        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(self.model_dump(), f, indent=2)