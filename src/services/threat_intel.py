from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from sqlalchemy.orm import Session
from src.models.models import ThreatIntel

class ThreatIntelService:
    @staticmethod
    def normalize_entity(value: str) -> str:
        """Extracts domain or IP from potential URL string."""
        if "://" in value:
            # Simple URL extraction
            return value.split("://")[1].split("/")[0].split(":")[0]
        return value.strip().lower()

    @staticmethod
    def check_entity(db: Session, value: str) -> Optional[Dict[str, Any]]:
        """
        Checks a domain or IP against the local threat intelligence cache.
        """
        normalized_value = ThreatIntelService.normalize_entity(value)
        # Local TTL check (30 days for demo persistence)
        expiration_limit = datetime.utcnow() - timedelta(days=30)
        
        intel = db.query(ThreatIntel).filter(
            ThreatIntel.entity_value == normalized_value,
            ThreatIntel.is_active == True,
            ThreatIntel.last_synced > expiration_limit
        ).first()
        
        if intel:
            return {
                "risk_level": intel.risk_level,
                "threat_type": intel.threat_type,
                "source": intel.source,
                "confidence": 95 if intel.risk_level == "critical" else 75
            }
        
        # In future, this is where external API calls to AbuseIPDB/VT would go
        # and then result would be cached in the ThreatIntel table.
        return None

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
