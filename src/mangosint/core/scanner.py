"""Main scanner module"""

import asyncio
from typing import Any, Dict, List, Optional

from mangosint.core.config import Config
from mangosint.core.correlation import CorrelationEngine
from mangosint.core.network import NetworkClient
from mangosint.core.output import ExportFormatter, OutputFormatter
from mangosint.modules.alienvault import AlienVaultModule
from mangosint.modules.asn import ASNModule
from mangosint.modules.censys import CensysModule
from mangosint.modules.certspotter import CertSpotterModule
from mangosint.modules.crtsh import CRTModule
from mangosint.modules.dns import DNSModule
from mangosint.modules.greynoise import GreyNoiseModule
from mangosint.modules.hibp import HIBPModule
from mangosint.modules.http import HTTPModule
from mangosint.modules.hunter import HunterModule
from mangosint.modules.ports import PortScanModule
from mangosint.modules.shodan import ShodanModule
from mangosint.modules.urlscan import URLScanModule
from mangosint.modules.virustotal import VirusTotalModule
from mangosint.modules.whois import WhoisModule


class Scanner:
    """Main scanner class"""

    def __init__(self, config: Config):
        self.config = config
        self.network_client = NetworkClient(config)
        self.correlation_engine = CorrelationEngine()
        self.modules = [
            DNSModule(config, self.network_client),
            CRTModule(config, self.network_client),
            CensysModule(config, self.network_client),
            ShodanModule(config, self.network_client),
            WhoisModule(config, self.network_client),
            VirusTotalModule(config, self.network_client),
            ASNModule(config, self.network_client),
            HTTPModule(config, self.network_client),
            PortScanModule(config, self.network_client),
            AlienVaultModule(config, self.network_client),
            CertSpotterModule(config, self.network_client),
            URLScanModule(config, self.network_client),
            HunterModule(config, self.network_client),
            HIBPModule(config, self.network_client),
            GreyNoiseModule(config, self.network_client),
        ]

    async def initialize(self):
        """Initialize scanner components"""
        await self.network_client.initialize()

    def _detect_target_type(self, target: str) -> str:
        """Detect target type"""
        # Simple detection logic
        if "." in target and not target.replace(".", "").replace(":", "").isdigit():
            return "domain"
        elif ":" in target:
            return "ip_port"
        elif target.replace(".", "").isdigit():
            return "ip"
        else:
            return "unknown"

    async def _run_module_scan(self, module, target: str, target_type: str) -> Dict[str, Any]:
        """Run a single module scan"""
        try:
            return await module.scan(target, target_type)
        except Exception as e:
            return {"error": str(e), "module": module.name}

    async def scan(
        self,
        target: str,
        deep: bool = False,
        passive_only: bool = False,
        active: bool = False,
        enabled_sources: Optional[List[str]] = None,
        disabled_sources: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Perform scan on target"""
        target_type = self._detect_target_type(target)

        # Filter modules
        modules_to_run = self.modules
        if enabled_sources:
            modules_to_run = [m for m in modules_to_run if m.name in enabled_sources]
        if disabled_sources:
            modules_to_run = [m for m in modules_to_run if m.name not in disabled_sources]

        # Filter out active modules if not enabled and not explicitly requested
        if not active:
            explicitly_enabled = set(enabled_sources or [])
            modules_to_run = [m for m in modules_to_run if "active" not in m.permissions or m.name in explicitly_enabled]

        # Run scans asynchronously
        tasks = [self._run_module_scan(module, target, target_type) for module in modules_to_run]
        module_results = await asyncio.gather(*tasks, return_exceptions=True)

        # Aggregate results
        aggregated = {
            "entity": target,
            "type": target_type,
            "attributes": {
                "ips": [],
                "ports": [],
                "services": {},
                "subdomains": [],
                "certificates": [],
                "technologies": [],
                "emails": [],
                "breaches": [],
                "security_headers": [],
                "ip_context": None,
                "asn": None,
                "organization": None,
                "registrar": None,
                "creation_date": None,
                "expiry_date": None,
                "reputation_score": None,
                "categories": [],
                "last_analysis_date": None,
                "threat_pulses": None,
                "threat_tags": [],
                "validation": None,
                "service_banners": {},
            },
            "sources": [],
            "errors": {},
            "confidence": 0.0,
        }

        for result in module_results:
            if isinstance(result, Exception):
                continue
            
            # Handle errors
            if "error" in result:
                # Store error by module name
                module_name = result.get("module", "unknown")
                aggregated["errors"][module_name] = result["error"]
                continue

            # Only add sources for successful modules
            if "sources" in result:
                aggregated["sources"].extend(result["sources"])
            
            # Update confidence
            if "confidence" in result and result["confidence"] > aggregated["confidence"]:
                aggregated["confidence"] = result["confidence"]
            
            # Merge successful attributes
            for key, value in result.items():
                if key in ["error", "sources", "confidence", "module"]:
                    continue  # Skip metadata keys
                elif key == "ips" and value:
                    # Handle both string IPs and detailed IP objects
                    for ip in value:
                        if isinstance(ip, str):
                            # Convert string IP to detailed object
                            ip_detail = {
                                "address": ip,
                                "asn": None,
                                "organization": None,
                                "isp": None,
                                "country": None,
                                "city": None,
                                "hostname": None
                            }
                            if ip_detail not in aggregated["attributes"]["ips"]:
                                aggregated["attributes"]["ips"].append(ip_detail)
                        elif isinstance(ip, dict):
                            # Already a detailed IP object
                            existing_ips = [existing["address"] for existing in aggregated["attributes"]["ips"]]
                            if ip["address"] not in existing_ips:
                                aggregated["attributes"]["ips"].append(ip)
                elif key == "ports" and value:
                    aggregated["attributes"]["ports"].extend(value)
                elif key == "services" and value:
                    aggregated["attributes"]["services"] = aggregated["attributes"].get("services", {})
                    aggregated["attributes"]["services"].update(value)
                elif key == "certificates" and value:
                    aggregated["attributes"]["certificates"].extend(value)
                elif key == "subdomains" and value:
                    aggregated["attributes"]["subdomains"].extend(value)
                elif key == "emails" and value:
                    aggregated["attributes"]["emails"].extend(value)
                elif key == "breaches" and value:
                    aggregated["attributes"]["breaches"].extend(value)
                elif key == "security_headers" and value:
                    aggregated["attributes"]["security_headers"].extend(value)
                elif key == "technologies" and value:
                    aggregated["attributes"]["technologies"].extend(value)
                elif key == "ip_context" and value:
                    # Store IP context information
                    aggregated["attributes"]["ip_context"] = value
                elif key == "organization" and value:
                    aggregated["attributes"]["organization"] = value
                elif key == "registrar" and value:
                    # Store registrar information
                    if "registrar" not in aggregated["attributes"]:
                        aggregated["attributes"]["registrar"] = value
                    else:
                        aggregated["attributes"]["registrar"] = value  # Overwrite
                elif key == "creation_date" and value:
                    if "creation_date" not in aggregated["attributes"]:
                        aggregated["attributes"]["creation_date"] = value
                elif key == "expiry_date" and value:
                    if "expiry_date" not in aggregated["attributes"]:
                        aggregated["attributes"]["expiry_date"] = value
                elif key == "reputation_score" and value is not None:
                    if "reputation_score" not in aggregated["attributes"]:
                        aggregated["attributes"]["reputation_score"] = value
                elif key == "categories" and value:
                    if "categories" not in aggregated["attributes"]:
                        aggregated["attributes"]["categories"] = value
                    else:
                        aggregated["attributes"]["categories"].extend(value)
                        aggregated["attributes"]["categories"] = list(set(aggregated["attributes"]["categories"]))
                elif key == "last_analysis_date" and value:
                    if "last_analysis_date" not in aggregated["attributes"]:
                        aggregated["attributes"]["last_analysis_date"] = value
                elif key == "threat_pulses" and value is not None:
                    if "threat_pulses" not in aggregated["attributes"]:
                        aggregated["attributes"]["threat_pulses"] = value
                elif key == "threat_tags" and value:
                    if "threat_tags" not in aggregated["attributes"]:
                        aggregated["attributes"]["threat_tags"] = value
                    else:
                        aggregated["attributes"]["threat_tags"].extend(value)
                        aggregated["attributes"]["threat_tags"] = list(set(aggregated["attributes"]["threat_tags"]))
                elif key == "validation" and value:
                    if "validation" not in aggregated["attributes"]:
                        aggregated["attributes"]["validation"] = value
                elif key == "service_banners" and value:
                    if "service_banners" not in aggregated["attributes"]:
                        aggregated["attributes"]["service_banners"] = value
                    else:
                        aggregated["attributes"]["service_banners"].update(value)

        # If this is a domain scan and we found IPs, scan those IPs too
        if target_type == "domain" and aggregated["attributes"]["ips"] and deep:
            ip_results = []
            for ip_detail in aggregated["attributes"]["ips"][:3]:  # Limit to first 3 IPs to avoid too many scans
                ip_address = ip_detail["address"] if isinstance(ip_detail, dict) else ip_detail
                ip_result = await self.scan(ip_address, deep=False, passive_only=passive_only, active=active,
                                          enabled_sources=enabled_sources, disabled_sources=disabled_sources)
                ip_results.append((ip_address, ip_result))

            # Merge IP scan results
            for ip_address, ip_result in ip_results:
                if "attributes" in ip_result:
                    ip_attrs = ip_result["attributes"]
                    
                    # Check if the IP scan returned updated IP information
                    if ip_attrs.get("ips"):
                        for updated_ip in ip_attrs["ips"]:
                            if updated_ip["address"] == ip_address:
                                # Update the corresponding IP detail with new information
                                for ip_detail in aggregated["attributes"]["ips"]:
                                    if isinstance(ip_detail, dict) and ip_detail["address"] == ip_address:
                                        # Merge the updated information
                                        for key, value in updated_ip.items():
                                            if value and not ip_detail.get(key):
                                                ip_detail[key] = value
                                        break
                                break
                    
                    # Update the corresponding IP detail with direct attributes from IP scan
                    for ip_detail in aggregated["attributes"]["ips"]:
                        if isinstance(ip_detail, dict) and ip_detail["address"] == ip_address:
                            # Update IP details with information from IP scan attributes
                            if ip_attrs.get("asn") and not ip_detail["asn"]:
                                ip_detail["asn"] = ip_attrs["asn"]
                            if ip_attrs.get("organization") and not ip_detail["organization"]:
                                ip_detail["organization"] = ip_attrs["organization"]
                            if ip_attrs.get("country") and not ip_detail["country"]:
                                ip_detail["country"] = ip_attrs["country"]
                            if ip_attrs.get("city") and not ip_detail["city"]:
                                ip_detail["city"] = ip_attrs["city"]
                            if ip_attrs.get("hostname") and not ip_detail["hostname"]:
                                ip_detail["hostname"] = ip_attrs["hostname"]
                            break
                    
                    # Add any additional subdomains, technologies, etc. found from IP scans
                    if ip_attrs.get("subdomains"):
                        aggregated["attributes"]["subdomains"].extend(ip_attrs["subdomains"])
                    if ip_attrs.get("technologies"):
                        aggregated["attributes"]["technologies"].extend(ip_attrs["technologies"])
                    # Note: We don't add sources from IP scans to avoid duplication

            # Remove duplicates
            aggregated["attributes"]["subdomains"] = list(set(aggregated["attributes"]["subdomains"]))
            aggregated["attributes"]["technologies"] = list(set(aggregated["attributes"]["technologies"]))
            aggregated["sources"] = list(set(aggregated["sources"]))

        return aggregated

    def output_results(
        self,
        results: Dict[str, Any],
        output_format: str = "json",
        export_format: Optional[str] = None,
    ) -> None:
        """Output results in specified format"""
        formatter = OutputFormatter(results)

        if output_format == "json":
            print(formatter.to_json())
        elif output_format == "txt":
            print(formatter.to_txt())
        elif output_format == "csv":
            print(formatter.to_csv())
        elif output_format == "html":
            print(formatter.to_html())
        elif output_format == "sqlite":
            formatter.to_sqlite()
            print("Results exported to results.db")
        else:
            print(formatter.to_json())  # Default to JSON

        if export_format:
            if isinstance(results, dict):
                results_list = [results]
            else:
                results_list = results

            exporter = ExportFormatter(results_list)

            if export_format == "graphml":
                with open("results.graphml", "w") as f:
                    f.write(exporter.to_graphml())
                print("GraphML export saved to results.graphml")
            elif export_format == "mermaid":
                with open("results.md", "w") as f:
                    f.write(exporter.to_mermaid())
                print("Mermaid export saved to results.md")