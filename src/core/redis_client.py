"""
Redis client for CyberGuard AI.

Provides an async Redis singleton with graceful degradation —
all operations return None / False when Redis is unavailable,
allowing the application to fall back to database queries.
"""

import json
import logging
from typing import Any, Optional

from src.core.config import settings

logger = logging.getLogger(__name__)

_redis_client: Optional[Any] = None
_redis_available: bool = False


def _make_client():
    """
    Attempt to create an async Redis client.
    Returns None if redis package is not installed or Redis is disabled.
    """
    if not settings.REDIS_ENABLED:
        return None
    try:
        import redis.asyncio as aioredis
        client = aioredis.from_url(
            settings.REDIS_URL,
            socket_timeout=settings.REDIS_SOCKET_TIMEOUT,
            socket_connect_timeout=settings.REDIS_SOCKET_CONNECT_TIMEOUT,
            decode_responses=True,
        )
        return client
    except ImportError:
        logger.warning("redis package not installed — Redis caching disabled")
        return None
    except Exception as exc:
        logger.warning(f"Redis client creation failed: {exc} — caching disabled")
        return None


async def get_redis() -> Optional[Any]:
    """
    Returns the async Redis client, or None if Redis is unavailable.
    Initialises lazily on first call.
    """
    global _redis_client, _redis_available

    if _redis_client is None:
        _redis_client = _make_client()

    if _redis_client is None:
        return None

    # Quick ping to verify connection
    if not _redis_available:
        try:
            await _redis_client.ping()
            _redis_available = True
            logger.info("Redis connection established")
        except Exception as exc:
            logger.debug(f"Redis ping failed: {exc}")
            _redis_available = False
            return None

    return _redis_client


async def get_cached(key: str) -> Optional[Any]:
    """
    Retrieve a JSON-decoded value from Redis cache.
    Returns None on miss or when Redis is unavailable.
    """
    client = await get_redis()
    if client is None:
        return None
    try:
        raw = await client.get(key)
        return json.loads(raw) if raw is not None else None
    except Exception as exc:
        logger.debug(f"Redis GET failed for key={key}: {exc}")
        return None


async def set_cached(key: str, value: Any, ttl: int = 300) -> bool:
    """
    JSON-encode and store a value in Redis with a TTL (seconds).
    Returns True on success, False on failure.
    """
    client = await get_redis()
    if client is None:
        return False
    try:
        await client.setex(key, ttl, json.dumps(value, default=str))
        return True
    except Exception as exc:
        logger.debug(f"Redis SET failed for key={key}: {exc}")
        return False


async def delete_cached(key: str) -> bool:
    """
    Delete a specific cache key.
    Returns True if the key was deleted, False otherwise.
    """
    client = await get_redis()
    if client is None:
        return False
    try:
        result = await client.delete(key)
        return result > 0
    except Exception as exc:
        logger.debug(f"Redis DELETE failed for key={key}: {exc}")
        return False


async def invalidate_pattern(pattern: str) -> int:
    """
    Delete all keys matching a glob pattern.
    Returns the number of keys deleted.
    """
    client = await get_redis()
    if client is None:
        return 0
    try:
        keys = await client.keys(pattern)
        if keys:
            return await client.delete(*keys)
        return 0
    except Exception as exc:
        logger.debug(f"Redis pattern invalidation failed for pattern={pattern}: {exc}")
        return 0


async def check_redis_health() -> dict:
    """
    Returns a health status dict for the /health endpoint.
    """
    global _redis_available
    client = await get_redis()
    if client is None:
        return {"status": "unavailable", "latency_ms": None, "reason": "disabled or not installed"}

    import time
    try:
        start = time.monotonic()
        await client.ping()
        latency_ms = round((time.monotonic() - start) * 1000, 2)
        _redis_available = True
        return {"status": "ok", "latency_ms": latency_ms}
    except Exception as exc:
        _redis_available = False
        return {"status": "unavailable", "latency_ms": None, "reason": str(exc)}


def build_key(*parts: str) -> str:
    """Build a namespaced Redis cache key."""
    return "cyberguard:" + ":".join(str(p) for p in parts)
