"""Base provider class and shared utilities for threat intelligence providers."""

from __future__ import annotations

import re
import logging
from typing import Optional

import httpx

from app.core import Settings, get_settings

logger = logging.getLogger(__name__)


class BaseProvider:
    """Base class for threat intelligence providers with shared HTTP client handling."""

    def __init__(
        self,
        settings: Optional[Settings] = None,
        *,
        http_client: Optional[httpx.Client] = None,
    ) -> None:
        self._settings = settings or get_settings()
        timeout = httpx.Timeout(10.0, connect=3.0)
        if http_client is not None:
            self._client = http_client
            self._owns_client = False
        else:
            self._client = httpx.Client(timeout=timeout)
            self._owns_client = True

    def __del__(self) -> None:
        if getattr(self, "_owns_client", False):
            try:
                self._client.close()
            except Exception:
                pass

    def close(self) -> None:
        """Explicitly close the HTTP client if owned."""
        if self._owns_client:
            self._client.close()


# =============================================================================
# IP Validation Utilities
# =============================================================================

def is_valid_public_ipv4(ip: str) -> bool:
    """Check if an IPv4 address is valid and public (not private/reserved)."""
    try:
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        octets = [int(p) for p in parts]
        if not all(0 <= o <= 255 for o in octets):
            return False
        first, second = octets[0], octets[1]
        # 0.x.x.x - Current network
        if first == 0:
            return False
        # 10.x.x.x - Private
        if first == 10:
            return False
        # 127.x.x.x - Loopback
        if first == 127:
            return False
        # 169.254.x.x - Link-local
        if first == 169 and second == 254:
            return False
        # 172.16.x.x - 172.31.x.x - Private
        if first == 172 and 16 <= second <= 31:
            return False
        # 192.168.x.x - Private
        if first == 192 and second == 168:
            return False
        # 224.x.x.x - 255.x.x.x - Multicast/Reserved
        if first >= 224:
            return False
        return True
    except (ValueError, IndexError):
        return False


def is_valid_public_ipv6(ip: str) -> bool:
    """Check if an IPv6 address is valid and public (not private/reserved)."""
    try:
        ip_lower = ip.lower().strip()
        if ip_lower == "::1" or ip_lower == "::":
            return False
        if ip_lower.startswith("fe80:"):
            return False
        if ip_lower.startswith("fc") or ip_lower.startswith("fd"):
            return False
        if ip_lower.startswith("ff"):
            return False
        if ":" not in ip:
            return False
        return True
    except (AttributeError, TypeError):
        # ip is not a string
        return False


# =============================================================================
# Domain Utilities
# =============================================================================

def normalize_domain(raw: str) -> str:
    """Normalize and validate a domain name."""
    if not raw:
        return ""
    d = raw.lower().strip().strip('.')
    pat = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])\.)+[a-z]{2,63}$")
    if not pat.match(d):
        return ""
    bad_tlds = {"local", "localhost", "lan", "home", "internal", "intranet", "invalid", "example", "test"}
    last = d.rsplit('.', 1)[-1]
    if last in bad_tlds:
        return ""
    allowed_tlds = {
        "com","net","org","io","co","gov","edu","mil","int","info","biz","me","us","uk","ca","au","de","fr","jp","cn","ru","in","nl","br","es","se","no","fi","dk","ch","it","pl","ro","cz","sk","be","at","nz","sg","hk","tw","tr","sa","ae","za","ar","mx","il","id","th","my","ph","vn","kr","pt","gr","ie"
    }
    if not (len(last) == 2 and last.isalpha()) and last not in allowed_tlds:
        return ""
    bad_exact = {"smtp.mailfrom", "header.from", "mailfrom", "helo", "mfrom", "pra", "fmarc", "dmarc", "spf"}
    if d in bad_exact:
        return ""
    return d


def is_urlscan_placeholder(screenshot: Optional[str]) -> bool:
    """Detect urlscan.io placeholder images that display 'No Screenshot Available'."""
    if not screenshot:
        return True
    if "No Screenshot" in screenshot:
        return True
    return screenshot.endswith(".png") and "/screenshots/" in screenshot
