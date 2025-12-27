"""Domain age and registration module for mangosint"""

import datetime
from typing import Any, Dict, List

from mangosint.core.config import Config
from mangosint.core.network import NetworkClient
from mangosint.modules.base import Module


class DomainAgeModule(Module):
    """Domain age and registration information module"""

    def __init__(self, config: Config, network_client: NetworkClient):
        super().__init__(config, network_client)

    @property
    def name(self) -> str:
        return "domainage"

    @property
    def description(self) -> str:
        return "Domain age and registration information"

    @property
    def permissions(self) -> List[str]:
        return ["network"]

    async def _get_domain_age(self, domain: str) -> Dict[str, Any]:
        """Get domain age information"""
        try:
            import whois

            # Query WHOIS
            w = whois.whois(domain)

            result = {}

            # Extract creation date
            if w.creation_date:
                if isinstance(w.creation_date, list):
                    creation_date = w.creation_date[0]
                else:
                    creation_date = w.creation_date

                if isinstance(creation_date, datetime.datetime):
                    result["creation_date"] = creation_date.isoformat()
                    
                    # Handle timezone-aware vs naive datetime comparison
                    now = datetime.datetime.now()
                    if creation_date.tzinfo is not None and now.tzinfo is None:
                        # creation_date is timezone-aware, make now aware
                        now = now.replace(tzinfo=creation_date.tzinfo)
                    elif creation_date.tzinfo is None and now.tzinfo is not None:
                        # now is timezone-aware, make creation_date aware
                        creation_date = creation_date.replace(tzinfo=now.tzinfo)
                    
                    result["age_days"] = (now - creation_date).days
                    result["age_years"] = result["age_days"] / 365.25

                    # Categorize domain age
                    if result["age_days"] < 30:
                        result["age_category"] = "very_new"
                    elif result["age_days"] < 365:
                        result["age_category"] = "new"
                    elif result["age_days"] < 365 * 5:
                        result["age_category"] = "established"
                    else:
                        result["age_category"] = "old"

            # Extract expiry date
            if w.expiration_date:
                if isinstance(w.expiration_date, list):
                    expiry_date = w.expiration_date[0]
                else:
                    expiry_date = w.expiration_date

                if isinstance(expiry_date, datetime.datetime):
                    result["expiry_date"] = expiry_date.isoformat()
                    
                    # Handle timezone-aware vs naive datetime comparison
                    now = datetime.datetime.now()
                    if expiry_date.tzinfo is not None and now.tzinfo is None:
                        now = now.replace(tzinfo=expiry_date.tzinfo)
                    elif expiry_date.tzinfo is None and now.tzinfo is not None:
                        expiry_date = expiry_date.replace(tzinfo=now.tzinfo)
                    
                    days_to_expiry = (expiry_date - now).days
                    result["days_to_expiry"] = max(0, days_to_expiry)

            # Extract registrar
            if w.registrar:
                result["registrar"] = str(w.registrar).strip()

            # Extract registrant info
            if w.name:
                result["registrant_name"] = str(w.name).strip()
            if w.org:
                result["registrant_org"] = str(w.org).strip()
            if w.country:
                result["registrant_country"] = str(w.country).strip()

            # Extract name servers
            if w.name_servers:
                if isinstance(w.name_servers, list):
                    result["name_servers"] = [str(ns).strip().lower() for ns in w.name_servers]
                else:
                    result["name_servers"] = [str(w.name_servers).strip().lower()]

            return result

        except ImportError:
            return {"error": "python-whois package not available"}
        except Exception as e:
            return {"error": str(e)}

    async def scan(self, target: str, target_type: str) -> Dict[str, Any]:
        """Perform domain age analysis"""
        if target_type != "domain":
            return {}

        try:
            domain_info = await self._get_domain_age(target)

            if "error" in domain_info:
                return {
                    "error": domain_info["error"],
                    "sources": ["domainage"],
                    "confidence": 0.0,
                }

            result = {
                "domain_info": domain_info,
                "sources": ["domainage"],
                "confidence": 0.8,
            }

            # Add risk assessment based on domain age
            if "age_category" in domain_info:
                age_category = domain_info["age_category"]
                if age_category == "very_new":
                    result["risk_assessment"] = "High risk - very new domain"
                elif age_category == "new":
                    result["risk_assessment"] = "Medium risk - relatively new domain"
                elif age_category == "established":
                    result["risk_assessment"] = "Low risk - established domain"
                else:
                    result["risk_assessment"] = "Very low risk - old domain"

            return result

        except Exception as e:
            return {
                "error": str(e),
                "sources": ["domainage"],
                "confidence": 0.0,
            }