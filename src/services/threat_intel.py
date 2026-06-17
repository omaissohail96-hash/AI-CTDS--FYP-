import ipaddress
import re
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from urllib.parse import urlparse
from sqlalchemy.orm import Session
from src.models.models import ThreatIntel

class ThreatIntelService:
    CACHE_TTL_SECONDS = 60 * 15
    _cache: Dict[str, Dict[str, Any]] = {}
    _domain_blacklist = {
        "evil-phishing.com": {"threat_type": "phishing", "risk_level": "critical", "source": "local-blacklist"},
        "malware-drop.ru": {"threat_type": "malware", "risk_level": "critical", "source": "local-blacklist"},
    }
    _ip_blacklist = {
        "192.168.1.100": {"threat_type": "botnet", "risk_level": "high", "source": "local-blacklist"},
        "45.9.148.201": {"threat_type": "command-and-control", "risk_level": "critical", "source": "local-blacklist"},
    }
    _url_blacklist = {
        "http://evil-phishing.com/login": {"threat_type": "credential-harvest", "risk_level": "critical", "source": "local-blacklist"},
    }

    @staticmethod
    def _cache_get(cache_key: str) -> Dict[str, Any]:
        cached = ThreatIntelService._cache.get(cache_key)
        if not cached:
            return {"hit": False, "value": None}
        if cached["expires_at"] < datetime.utcnow():
            ThreatIntelService._cache.pop(cache_key, None)
            return {"hit": False, "value": None}
        return {"hit": True, "value": cached["value"]}

    @staticmethod
    def _cache_set(cache_key: str, value: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        ThreatIntelService._cache[cache_key] = {
            "value": value,
            "expires_at": datetime.utcnow() + timedelta(seconds=ThreatIntelService.CACHE_TTL_SECONDS),
        }
        return value

    @staticmethod
    def _is_ip(value: str) -> bool:
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    @staticmethod
    def _extract_url(value: str) -> Optional[str]:
        if isinstance(value, str) and value.startswith(("http://", "https://")):
            return value.strip()
        return None

    @staticmethod
    def extract_entities(value: Any) -> List[str]:
        if isinstance(value, dict):
            raw_text = " ".join(str(v) for v in value.values())
        else:
            raw_text = str(value or "")

        entities = set()
        url_matches = re.findall(r"https?://[^\s\"'<>]+", raw_text, flags=re.IGNORECASE)
        domain_matches = re.findall(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", raw_text, flags=re.IGNORECASE)
        ip_matches = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", raw_text)

        for url in url_matches:
            entities.add(url.strip())
            normalized_domain = ThreatIntelService.normalize_entity(url)
            if normalized_domain:
                entities.add(normalized_domain)

        for domain in domain_matches:
            entities.add(domain.lower())

        for ip in ip_matches:
            entities.add(ip)

        return sorted(entities)

    @staticmethod
    def normalize_entity(value: str) -> str:
        """Extracts domain or IP from potential URL string."""
        if not value:
            return ""
        if "://" in value:
            parsed = urlparse(value.strip())
            return parsed.netloc.split(":")[0].lower()
        return value.strip().lower()

    @staticmethod
    def check_entity(db: Session, value: str) -> Optional[Dict[str, Any]]:
        """
        Checks a domain or IP against the local threat intelligence cache.
        """
        normalized_value = ThreatIntelService.normalize_entity(value)
        url_value = ThreatIntelService._extract_url(value)
        cache_key = f"{url_value or normalized_value}"
        cached = ThreatIntelService._cache_get(cache_key)
        if cached["hit"]:
            return cached["value"]

        if url_value and url_value.lower() in ThreatIntelService._url_blacklist:
            hit = {
                **ThreatIntelService._url_blacklist[url_value.lower()],
                "confidence": 99,
                "entity": url_value.lower(),
                "entity_type": "url",
            }
            return ThreatIntelService._cache_set(cache_key, hit)

        if normalized_value in ThreatIntelService._domain_blacklist:
            hit = {
                **ThreatIntelService._domain_blacklist[normalized_value],
                "confidence": 95,
                "entity": normalized_value,
                "entity_type": "ip" if ThreatIntelService._is_ip(normalized_value) else "domain",
            }
            return ThreatIntelService._cache_set(cache_key, hit)

        if normalized_value in ThreatIntelService._ip_blacklist:
            hit = {
                **ThreatIntelService._ip_blacklist[normalized_value],
                "confidence": 95,
                "entity": normalized_value,
                "entity_type": "ip",
            }
            return ThreatIntelService._cache_set(cache_key, hit)

        # Local TTL check (30 days for demo persistence)
        expiration_limit = datetime.utcnow() - timedelta(days=30)
        
        intel = db.query(ThreatIntel).filter(
            ThreatIntel.entity_value == normalized_value,
            ThreatIntel.is_active == True,
            ThreatIntel.last_synced > expiration_limit
        ).first()
        
        if intel:
            hit = {
                "risk_level": intel.risk_level,
                "threat_type": intel.threat_type,
                "source": intel.source,
                "confidence": 95 if intel.risk_level == "critical" else 75,
                "entity": normalized_value,
                "entity_type": intel.entity_type,
            }
            return ThreatIntelService._cache_set(cache_key, hit)
        
        # In future, this is where external API calls to AbuseIPDB/VT would go
        # and then result would be cached in the ThreatIntel table.
        return ThreatIntelService._cache_set(cache_key, None)

    @staticmethod
    def seed_intel(db: Session, value: str, entity_type: str, threat_type: str, risk_level: str):
        """Helper to seed internal blacklists"""
        intel = ThreatIntel(
            entity_value=value,
            entity_type=entity_type,
            threat_type=threat_type,
            risk_level=risk_level,
            source="local"
        )
        db.add(intel)
        db.commit()
