"""Correlation and enrichment engine"""

from typing import Any, Dict, List, Set
from collections import defaultdict


class CorrelationEngine:
    """Correlates intelligence across sources"""

    def __init__(self):
        self.correlations = []

    def correlate(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Correlate results across all targets"""
        if not results:
            return {}

        # Collect all entities and their attributes
        entities = {}
        all_ips = set()
        all_subdomains = set()
        all_technologies = set()
        all_organizations = set()
        all_asns = set()

        for result in results:
            entity = result.get("entity", "")
            if not entity:
                continue

            entities[entity] = result
            attributes = result.get("attributes", {})

            # Collect all IPs, subdomains, etc.
            all_ips.update(attributes.get("ips", []))
            all_subdomains.update(attributes.get("subdomains", []))
            all_technologies.update(attributes.get("technologies", []))
            all_organizations.add(attributes.get("organization"))
            all_asns.add(attributes.get("asn"))

        # Remove None values
        all_organizations.discard(None)
        all_asns.discard(None)

        # Find correlations
        correlations = {
            "shared_ips": self._find_shared_entities(entities, "ips"),
            "shared_subdomains": self._find_shared_entities(entities, "subdomains"),
            "shared_technologies": self._find_shared_entities(entities, "technologies"),
            "infrastructure_clusters": self._cluster_by_organization(entities),
            "asn_groupings": self._group_by_asn(entities),
        }

        return correlations

    def _find_shared_entities(self, entities: Dict[str, Dict], attr_key: str) -> List[Dict[str, Any]]:
        """Find entities that share common attributes"""
        attr_to_entities = defaultdict(set)

        for entity, data in entities.items():
            attributes = data.get("attributes", {})
            attr_values = attributes.get(attr_key, [])
            if isinstance(attr_values, list):
                for value in attr_values:
                    attr_to_entities[value].add(entity)
            elif attr_values:
                attr_to_entities[attr_values].add(entity)

        # Find shared attributes
        shared = []
        for attr_value, entity_set in attr_to_entities.items():
            if len(entity_set) > 1:
                shared.append({
                    "attribute": attr_key,
                    "value": attr_value,
                    "entities": list(entity_set),
                    "count": len(entity_set)
                })

        return shared

    def _cluster_by_organization(self, entities: Dict[str, Dict]) -> List[Dict[str, Any]]:
        """Cluster entities by organization"""
        org_to_entities = defaultdict(list)

        for entity, data in entities.items():
            attributes = data.get("attributes", {})
            org = attributes.get("organization")
            if org:
                org_to_entities[org].append(entity)

        clusters = []
        for org, entity_list in org_to_entities.items():
            if len(entity_list) > 1:
                clusters.append({
                    "organization": org,
                    "entities": entity_list,
                    "count": len(entity_list)
                })

        return clusters

    def _group_by_asn(self, entities: Dict[str, Dict]) -> List[Dict[str, Any]]:
        """Group entities by ASN"""
        asn_to_entities = defaultdict(list)

        for entity, data in entities.items():
            attributes = data.get("attributes", {})
            asn = attributes.get("asn")
            if asn:
                asn_to_entities[asn].append(entity)

        groups = []
        for asn, entity_list in asn_to_entities.items():
            if len(entity_list) > 1:
                groups.append({
                    "asn": asn,
                    "entities": entity_list,
                    "count": len(entity_list)
                })

        return groups

    def enrich_results(self, results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Enrich individual results with correlation data"""
        correlations = self.correlate(results)

        # Add correlation insights to each result
        enriched = []
        for result in results:
            enriched_result = result.copy()
            entity = result.get("entity", "")

            # Add correlation insights
            insights = []

            # Check shared IPs
            for shared in correlations.get("shared_ips", []):
                if entity in shared["entities"]:
                    insights.append(f"Shares IP {shared['value']} with {len(shared['entities'])-1} other entities")

            # Check shared subdomains
            for shared in correlations.get("shared_subdomains", []):
                if entity in shared["entities"]:
                    insights.append(f"Shares subdomain pattern with {len(shared['entities'])-1} other entities")

            # Check infrastructure clusters
            for cluster in correlations.get("infrastructure_clusters", []):
                if entity in cluster["entities"]:
                    insights.append(f"Part of infrastructure cluster owned by {cluster['organization']}")

            if insights:
                enriched_result["correlation_insights"] = insights

            enriched.append(enriched_result)

        return enriched