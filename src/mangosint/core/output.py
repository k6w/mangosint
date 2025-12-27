"""Output formatting and export system"""

import csv
import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional


class OutputFormatter:
    """Handles various output formats"""

    def __init__(self, results: Dict[str, Any]):
        self.results = results

    def _clean_empty_values(self, obj: Any) -> Any:
        """Recursively remove empty values from dict/list structures"""
        if isinstance(obj, dict):
            return {k: self._clean_empty_values(v) for k, v in obj.items() 
                   if v is not None and v != "" and v != [] and v != {}}
        elif isinstance(obj, list):
            cleaned_list = [self._clean_empty_values(item) for item in obj]
            return [item for item in cleaned_list if item is not None and item != "" and item != [] and item != {}]
        else:
            return obj

    def to_json(self) -> str:
        """Output as JSON"""
        cleaned_results = self._clean_empty_values(self.results)
        return json.dumps(cleaned_results, indent=2, default=str)

    def to_txt(self) -> str:
        """Output as human-readable text"""
        lines = []

        entity = self.results.get("entity", "Unknown")
        entity_type = self.results.get("type", "unknown")

        lines.append(f"Entity: {entity} ({entity_type})")
        lines.append(f"Confidence: {self.results.get('confidence', 0.0):.2f}")
        lines.append(f"Sources: {', '.join(self.results.get('sources', []))}")
        lines.append("")

        # Show errors if any
        errors = self.results.get("errors", {})
        if errors:
            lines.append("Errors:")
            for module, error in errors.items():
                lines.append(f"  - {module}: {error}")
            lines.append("")

        attributes = self.results.get("attributes", {})

        if attributes.get("ips"):
            lines.append("IP Addresses:")
            for ip in attributes["ips"]:
                if isinstance(ip, dict):
                    ip_info = ip["address"]
                    if ip.get("organization"):
                        ip_info += f" ({ip['organization']})"
                    if ip.get("country"):
                        ip_info += f" - {ip['country']}"
                    if ip.get("asn"):
                        ip_info += f" [ASN: {ip['asn']}]"
                    lines.append(f"  - {ip_info}")
                else:
                    lines.append(f"  - {ip}")
            lines.append("")

        if attributes.get("subdomains"):
            lines.append("Subdomains:")
            for subdomain in attributes["subdomains"]:
                lines.append(f"  - {subdomain}")
            lines.append("")

        if attributes.get("ports"):
            lines.append("Ports:")
            for port in attributes["ports"]:
                lines.append(f"  - {port}")
            lines.append("")

        if attributes.get("certificates"):
            lines.append("Certificates:")
            for cert in attributes["certificates"][:5]:  # Limit to 5
                lines.append(f"  - {cert.get('subject', 'Unknown')} (expires: {cert.get('not_after', 'Unknown')})")
            lines.append("")

        return "\n".join(lines)

    def to_csv(self) -> str:
        """Output as CSV"""
        # Flatten the data
        rows = []

        entity = self.results.get("entity", "")
        attributes = self.results.get("attributes", {})

        # IPs
        for ip in attributes.get("ips", []):
            if isinstance(ip, dict):
                rows.append({
                    "entity": entity,
                    "type": "ip",
                    "value": ip["address"],
                    "organization": ip.get("organization", ""),
                    "asn": ip.get("asn", ""),
                    "country": ip.get("country", ""),
                    "confidence": self.results.get("confidence", 0.0)
                })
            else:
                rows.append({
                    "entity": entity,
                    "type": "ip",
                    "value": ip,
                    "organization": "",
                    "asn": "",
                    "country": "",
                    "confidence": self.results.get("confidence", 0.0)
                })

        # Subdomains
        for subdomain in attributes.get("subdomains", []):
            rows.append({
                "entity": entity,
                "type": "subdomain",
                "value": subdomain,
                "confidence": self.results.get("confidence", 0.0)
            })

        # Ports
        for port in attributes.get("ports", []):
            rows.append({
                "entity": entity,
                "type": "port",
                "value": port,
                "confidence": self.results.get("confidence", 0.0)
            })

        if not rows:
            # At least one row
            rows.append({
                "entity": entity,
                "type": "entity",
                "value": entity,
                "confidence": self.results.get("confidence", 0.0)
            })

        # Convert to CSV
        import io
        output = io.StringIO()
        if rows:
            fieldnames = ["entity", "type", "value", "organization", "asn", "country", "confidence"]
            writer = csv.DictWriter(output, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)

        return output.getvalue()

    def to_sqlite(self, db_path: str = "results.db") -> None:
        """Export to SQLite database"""
        conn = sqlite3.connect(db_path)

        # Create tables
        conn.execute("""
            CREATE TABLE IF NOT EXISTS entities (
                id INTEGER PRIMARY KEY,
                entity TEXT,
                type TEXT,
                confidence REAL,
                sources TEXT
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS attributes (
                id INTEGER PRIMARY KEY,
                entity_id INTEGER,
                attr_type TEXT,
                value TEXT,
                FOREIGN KEY (entity_id) REFERENCES entities (id)
            )
        """)

        # Insert data
        entity = self.results.get("entity", "")
        entity_type = self.results.get("type", "")
        confidence = self.results.get("confidence", 0.0)
        sources = json.dumps(self.results.get("sources", []))

        cursor = conn.execute(
            "INSERT INTO entities (entity, type, confidence, sources) VALUES (?, ?, ?, ?)",
            (entity, entity_type, confidence, sources)
        )
        entity_id = cursor.lastrowid

        # Clean attributes before inserting
        cleaned_attributes = self._clean_empty_values(self.results.get("attributes", {}))
        
        for attr_type, values in cleaned_attributes.items():
            if isinstance(values, list):
                for value in values:
                    if value is not None and value != "" and value != [] and value != {}:
                        conn.execute(
                            "INSERT INTO attributes (entity_id, attr_type, value) VALUES (?, ?, ?)",
                            (entity_id, attr_type, str(value))
                        )
            elif values is not None and values != "" and values != [] and values != {}:
                conn.execute(
                    "INSERT INTO attributes (entity_id, attr_type, value) VALUES (?, ?, ?)",
                    (entity_id, attr_type, str(values))
                )

        conn.commit()
        conn.close()

    def to_html(self) -> str:
        """Output as HTML"""
        entity = self.results.get("entity", "Unknown")
        attributes = self.results.get("attributes", {})

        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>OSINT Results for {entity}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .section {{ margin-bottom: 20px; }}
                .attribute {{ background: #f5f5f5; padding: 10px; margin: 5px 0; }}
                h2 {{ color: #333; }}
            </style>
        </head>
        <body>
            <h1>OSINT Results for {entity}</h1>
            <p>Type: {self.results.get('type', 'unknown')}</p>
            <p>Confidence: {self.results.get('confidence', 0.0):.2f}</p>
            <p>Sources: {', '.join(self.results.get('sources', []))}</p>
        """

        for attr_name, values in attributes.items():
            if values:
                html += f"<div class='section'><h2>{attr_name.title()}</h2>"
                if isinstance(values, list):
                    for value in values:
                        if isinstance(value, dict) and attr_name == "ips":
                            # Special handling for IP details
                            ip_info = value["address"]
                            details = []
                            if value.get("organization"):
                                details.append(f"Org: {value['organization']}")
                            if value.get("asn"):
                                details.append(f"ASN: {value['asn']}")
                            if value.get("country"):
                                details.append(f"Country: {value['country']}")
                            if value.get("city"):
                                details.append(f"City: {value['city']}")
                            if details:
                                ip_info += f" ({', '.join(details)})"
                            html += f"<div class='attribute'>{ip_info}</div>"
                        else:
                            html += f"<div class='attribute'>{value}</div>"
                else:
                    html += f"<div class='attribute'>{values}</div>"
                html += "</div>"

        html += "</body></html>"
        return html


class ExportFormatter:
    """Handles export formats like GraphML, Neo4j, etc."""

    def __init__(self, results: List[Dict[str, Any]]):
        self.results = results

    def to_graphml(self) -> str:
        """Export as GraphML format"""
        # Simple GraphML generation
        graphml = """<?xml version="1.0" encoding="UTF-8"?>
        <graphml xmlns="http://graphml.graphdrawing.org/xmlns"
                 xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                 xsi:schemaLocation="http://graphml.graphdrawing.org/xmlns
                                     http://graphml.graphdrawing.org/xmlns/1.0/graphml.xsd">
          <key id="entity_type" for="node" attr.name="entity_type" attr.type="string"/>
          <key id="confidence" for="node" attr.name="confidence" attr.type="double"/>
          <graph id="G" edgedefault="undirected">
        """

        node_id = 0
        edges = []

        for result in self.results:
            entity = result.get("entity", "")
            entity_type = result.get("type", "")
            confidence = result.get("confidence", 0.0)
            attributes = result.get("attributes", {})

            # Add main entity node
            graphml += f'    <node id="n{node_id}">\n'
            graphml += f'      <data key="entity_type">{entity_type}</data>\n'
            graphml += f'      <data key="confidence">{confidence}</data>\n'
            graphml += f'    </node>\n'
            entity_node_id = node_id
            node_id += 1

            # Add attribute nodes and edges
            for attr_type, values in attributes.items():
                if isinstance(values, list):
                    for value in values:
                        graphml += f'    <node id="n{node_id}">\n'
                        graphml += f'      <data key="entity_type">{attr_type}</data>\n'
                        graphml += f'    </node>\n'
                        edges.append((entity_node_id, node_id, f"has_{attr_type}"))
                        node_id += 1
                elif values:
                    graphml += f'    <node id="n{node_id}">\n'
                    graphml += f'      <data key="entity_type">{attr_type}</data>\n'
                    graphml += f'    </node>\n'
                    edges.append((entity_node_id, node_id, f"has_{attr_type}"))
                    node_id += 1

        # Add edges
        for source, target, label in edges:
            graphml += f'    <edge source="n{source}" target="n{target}"/>\n'

        graphml += "  </graph>\n</graphml>"
        return graphml

    def to_mermaid(self) -> str:
        """Export as Mermaid format"""
        mermaid = "graph TD\n"

        node_id = 0
        node_map = {}

        for result in self.results:
            entity = result.get("entity", "")
            attributes = result.get("attributes", {})

            if entity not in node_map:
                node_map[entity] = f"N{node_id}"
                mermaid += f"    {node_map[entity]}[{entity}]\n"
                node_id += 1

            for attr_type, values in attributes.items():
                if isinstance(values, list):
                    for value in values:
                        value_id = f"N{node_id}"
                        mermaid += f"    {value_id}[{value}]\n"
                        mermaid += f"    {node_map[entity]} --> {value_id}\n"
                        node_id += 1
                elif values:
                    value_id = f"N{node_id}"
                    mermaid += f"    {value_id}[{values}]\n"
                    mermaid += f"    {node_map[entity]} --> {value_id}\n"
                    node_id += 1

        return mermaid