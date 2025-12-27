"""Input normalization and target processing"""

import asyncio
import os
from typing import Dict, List

from rich.console import Console

console = Console()

from mangosint.core.config import Config
from mangosint.core.correlation import CorrelationEngine
from mangosint.core.network import NetworkClient
from mangosint.core.scanner import Scanner


class InputNormalizer:
    """Normalizes various input formats into scan targets"""

    def __init__(self, config: Config, network_client: NetworkClient):
        self.config = config
        self.network_client = network_client

    def normalize_target(self, target: str) -> str:
        """Normalize a single target"""
        target = target.strip()

        # Handle URLs
        if target.startswith("http://") or target.startswith("https://"):
            # Extract host and port
            from urllib.parse import urlparse
            parsed = urlparse(target)
            host = parsed.hostname
            port = parsed.port
            if port:
                return f"{host}:{port}"
            return host

        # Handle IP:PORT
        if ":" in target and target.replace(".", "").replace(":", "").replace("/", "").isdigit():
            return target

        # Clean domain
        return target.lower()

    async def load_targets_from_file(self, file_path: str) -> List[str]:
        """Load targets from file"""
        targets = []

        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Target file not found: {file_path}")

        with open(file_path, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    targets.append(self.normalize_target(line))

        return targets

    async def process_input(self, input_target: str) -> List[str]:
        """Process input and return list of targets"""
        # Check if it's a file
        if os.path.isfile(input_target):
            return await self.load_targets_from_file(input_target)

        # Single target
        return [self.normalize_target(input_target)]


class BatchScanner:
    """Handles scanning multiple targets"""

    def __init__(self, config: Config):
        self.config = config
        self.input_normalizer = InputNormalizer(config, NetworkClient(config))
        self.scanner = Scanner(config)

    async def initialize(self):
        """Initialize components"""
        await self.scanner.initialize()

    async def scan_batch(self, targets: List[str], **scan_kwargs) -> List[Dict]:
        """Scan multiple targets"""
        results = []

        for target in targets:
            console.print(f"[bold blue]Scanning:[/bold blue] {target}")
            result = await self.scanner.scan(target, **scan_kwargs)
            results.append(result)

            # Rate limiting between targets
            await asyncio.sleep(0.5)

        # Apply correlation
        if len(results) > 1:
            correlation_engine = CorrelationEngine()
            results = correlation_engine.enrich_results(results)

            # Add overall correlation summary
            correlations = correlation_engine.correlate(results)
            if correlations:
                results.append({
                    "entity": "CORRELATION_SUMMARY",
                    "type": "correlation",
                    "attributes": {},
                    "correlations": correlations,
                    "sources": ["correlation_engine"],
                    "confidence": 1.0
                })

        return results