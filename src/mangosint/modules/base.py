"""Base module class for plugins"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List

from mangosint.core.config import Config
from mangosint.core.network import NetworkClient


class Module(ABC):
    """Base class for all modules"""

    def __init__(self, config: Config, network_client: NetworkClient):
        self.config = config
        self.network_client = network_client

    @property
    @abstractmethod
    def name(self) -> str:
        """Module name"""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Module description"""
        pass

    @property
    @abstractmethod
    def permissions(self) -> List[str]:
        """Required permissions"""
        pass

    @abstractmethod
    async def scan(self, target: str, target_type: str) -> Dict[str, Any]:
        """Perform scan"""
        pass