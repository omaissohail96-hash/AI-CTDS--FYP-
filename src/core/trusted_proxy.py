"""
Trusted Proxy Resolver for CyberGuard AI.

Prevents IP spoofing by only trusting X-Forwarded-For / X-Real-IP headers
from explicitly configured reverse proxy addresses.
"""

import logging
import ipaddress
from typing import List, Optional

from fastapi import Request

logger = logging.getLogger(__name__)


class TrustedProxyResolver:
    """
    Validates client IP extraction against a configurable list of trusted proxies.

    Security model:
    - If the connecting IP is in TRUSTED_PROXIES → trust X-Forwarded-For header
    - Otherwise → use request.client.host directly (ignore forwarded headers)
    - Log any suspicious header manipulation attempts
    """

    def __init__(self, trusted_proxies: List[str]):
        self._networks: List[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for proxy in trusted_proxies:
            try:
                self._networks.append(ipaddress.ip_network(proxy, strict=False))
            except ValueError:
                logger.warning(f"TrustedProxy: invalid proxy entry ignored: {proxy!r}")

    def get_client_ip(self, request: Request) -> str:
        """
        Extract the real client IP, validating proxy headers.

        Returns the resolved IP string, or 'unknown' if not determinable.
        """
        connecting_ip = request.client.host if request.client else None

        # If there are no trusted proxies configured, skip header inspection
        if not self._networks or connecting_ip is None:
            return connecting_ip or "unknown"

        if self._is_trusted(connecting_ip):
            # Connecting host is a trusted proxy → read forwarded headers
            xff = request.headers.get("x-forwarded-for")
            if xff:
                # XFF contains a comma-separated chain; leftmost is the original client
                client_ip = xff.split(",")[0].strip()
                if self._is_valid_ip(client_ip):
                    return client_ip
                else:
                    logger.warning(
                        f"Suspicious X-Forwarded-For value {xff!r} from proxy {connecting_ip}; "
                        "falling back to proxy IP"
                    )
                    return connecting_ip

            real_ip = request.headers.get("x-real-ip")
            if real_ip and self._is_valid_ip(real_ip.strip()):
                return real_ip.strip()

            return connecting_ip
        else:
            # Connecting host is NOT a trusted proxy
            # Check if it's trying to inject forwarded headers — suspicious!
            xff = request.headers.get("x-forwarded-for")
            if xff:
                logger.warning(
                    f"Untrusted host {connecting_ip} sent X-Forwarded-For: {xff!r} — "
                    "header ignored (possible IP spoofing attempt)"
                )
            real_ip = request.headers.get("x-real-ip")
            if real_ip:
                logger.warning(
                    f"Untrusted host {connecting_ip} sent X-Real-IP: {real_ip!r} — "
                    "header ignored"
                )
            return connecting_ip

    def _is_trusted(self, ip_str: str) -> bool:
        """Check if the given IP belongs to a trusted proxy network."""
        try:
            ip = ipaddress.ip_address(ip_str)
            return any(ip in network for network in self._networks)
        except ValueError:
            return False

    @staticmethod
    def _is_valid_ip(ip_str: str) -> bool:
        """Validate that a string is a well-formed IP address."""
        try:
            ipaddress.ip_address(ip_str)
            return True
        except ValueError:
            return False


# ── Module-level singleton ────────────────────────────────────────────────────
_resolver: Optional[TrustedProxyResolver] = None


def get_resolver() -> TrustedProxyResolver:
    """Return the module-level TrustedProxyResolver (lazy init)."""
    global _resolver
    if _resolver is None:
        from src.core.config import settings
        _resolver = TrustedProxyResolver(settings.trusted_proxies_list)
    return _resolver


def get_client_ip(request: Request) -> str:
    """
    Convenience function: resolve client IP from request using trusted proxy rules.
    This is the single authoritative IP extraction point for the entire application.
    """
    return get_resolver().get_client_ip(request)
