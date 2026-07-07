"""
Redis Cache Service for CyberGuard AI.

Provides a unified caching layer for hot-path database lookups:
  - Blocked entities (checked on every middleware request)
  - Threat intelligence indicators
  - User behavior profiles
  - API key metadata
  - Workspace quotas

All methods degrade gracefully to database fallback when Redis is unavailable.
"""

import logging
from datetime import datetime
from typing import Any, Dict, Optional
import uuid

from sqlalchemy.orm import Session
from sqlalchemy import and_

from src.core.redis_client import get_cached, set_cached, delete_cached, invalidate_pattern, build_key
from src.core.config import settings

logger = logging.getLogger(__name__)


class CacheService:
    """
    Centralized cache service with DB fallback.

    Usage pattern:
        result = await CacheService.get_blocked_entity(workspace_id, entity)
        if result is None:
            result = db_query(...)
            await CacheService.set_blocked_entity(workspace_id, entity, result)
    """

    # ── Blocked Entities ──────────────────────────────────────────────────────

    @staticmethod
    async def get_blocked_entity(workspace_id: str, entity: str) -> Optional[Dict]:
        key = build_key(workspace_id, "blocked", entity)
        return await get_cached(key)

    @staticmethod
    async def set_blocked_entity(workspace_id: str, entity: str, data: Dict, blocked_until: datetime) -> bool:
        key = build_key(workspace_id, "blocked", entity)
        ttl = max(1, int((blocked_until - datetime.utcnow()).total_seconds()))
        ttl = min(ttl, settings.CACHE_TTL_BLOCKED_ENTITY)
        return await set_cached(key, data, ttl=ttl)

    @staticmethod
    async def invalidate_blocked_entity(workspace_id: str, entity: str) -> bool:
        key = build_key(workspace_id, "blocked", entity)
        return await delete_cached(key)

    @staticmethod
    async def invalidate_all_blocked(workspace_id: str) -> int:
        pattern = build_key(workspace_id, "blocked", "*")
        return await invalidate_pattern(pattern)

    # ── Threat Intelligence ───────────────────────────────────────────────────

    @staticmethod
    async def get_threat_intel(entity: str) -> Optional[Dict]:
        key = build_key("intel", entity)
        return await get_cached(key)

    @staticmethod
    async def set_threat_intel(entity: str, data: Optional[Dict]) -> bool:
        key = build_key("intel", entity)
        # Cache both hits and misses (negative caching prevents DB hammering)
        payload = data if data is not None else {"__miss__": True}
        return await set_cached(key, payload, ttl=settings.CACHE_TTL_THREAT_INTEL)

    @staticmethod
    async def invalidate_threat_intel(entity: str) -> bool:
        return await delete_cached(build_key("intel", entity))

    @staticmethod
    async def invalidate_all_threat_intel() -> int:
        return await invalidate_pattern(build_key("intel", "*"))

    # ── UBA Profiles ─────────────────────────────────────────────────────────

    @staticmethod
    async def get_uba_profile(workspace_id: str, user_id: str) -> Optional[Dict]:
        key = build_key(workspace_id, "uba", user_id)
        return await get_cached(key)

    @staticmethod
    async def set_uba_profile(workspace_id: str, user_id: str, data: Dict) -> bool:
        key = build_key(workspace_id, "uba", user_id)
        return await set_cached(key, data, ttl=settings.CACHE_TTL_UBA_PROFILE)

    @staticmethod
    async def invalidate_uba_profile(workspace_id: str, user_id: str) -> bool:
        return await delete_cached(build_key(workspace_id, "uba", user_id))

    # ── API Key Metadata ──────────────────────────────────────────────────────

    @staticmethod
    async def get_api_key(key_hash: str) -> Optional[Dict]:
        key = build_key("apikey", key_hash)
        return await get_cached(key)

    @staticmethod
    async def set_api_key(key_hash: str, data: Dict) -> bool:
        key = build_key("apikey", key_hash)
        return await set_cached(key, data, ttl=settings.CACHE_TTL_API_KEY)

    @staticmethod
    async def invalidate_api_key(key_hash: str) -> bool:
        return await delete_cached(build_key("apikey", key_hash))

    # ── Workspace Quota ───────────────────────────────────────────────────────

    @staticmethod
    async def get_workspace_quota(workspace_id: str) -> Optional[Dict]:
        key = build_key(workspace_id, "quota")
        return await get_cached(key)

    @staticmethod
    async def set_workspace_quota(workspace_id: str, data: Dict) -> bool:
        key = build_key(workspace_id, "quota")
        return await set_cached(key, data, ttl=settings.CACHE_TTL_WORKSPACE_QUOTA)

    @staticmethod
    async def invalidate_workspace_quota(workspace_id: str) -> bool:
        return await delete_cached(build_key(workspace_id, "quota"))

    # ── Cache Warming ─────────────────────────────────────────────────────────

    @staticmethod
    async def warm_cache_on_startup(db: Session) -> Dict[str, int]:
        """
        Pre-populate Redis with hot-path data on application startup.
        Returns counts of warmed cache entries per category.
        """
        from src.models.models import BlockedEntity, ThreatIntel
        counts = {"blocked_entities": 0, "threat_intel": 0}

        now = datetime.utcnow()

        # Warm active blocked entities
        try:
            active_blocks = db.query(BlockedEntity).filter(
                and_(
                    BlockedEntity.blocked_until > now,
                    BlockedEntity.resolved_status == False,
                )
            ).all()

            for block in active_blocks:
                data = {
                    "id": str(block.id),
                    "entity": block.entity,
                    "entity_type": block.entity_type,
                    "severity": block.severity,
                    "reason": block.reason,
                    "blocked_until": block.blocked_until.isoformat(),
                }
                ok = await CacheService.set_blocked_entity(
                    str(block.workspace_id), block.entity, data, block.blocked_until
                )
                if ok:
                    counts["blocked_entities"] += 1
        except Exception as exc:
            logger.warning(f"Cache warming (blocked entities) failed: {exc}")

        # Warm active threat intel
        try:
            intel_entries = db.query(ThreatIntel).filter(
                ThreatIntel.is_active == True
            ).limit(5000).all()

            for entry in intel_entries:
                data = {
                    "entity_value": entry.entity_value,
                    "entity_type": entry.entity_type,
                    "threat_type": entry.threat_type,
                    "risk_level": entry.risk_level,
                    "source": entry.source,
                }
                ok = await CacheService.set_threat_intel(entry.entity_value, data)
                if ok:
                    counts["threat_intel"] += 1
        except Exception as exc:
            logger.warning(f"Cache warming (threat intel) failed: {exc}")

        logger.info(f"Cache warming complete: {counts}")
        return counts
