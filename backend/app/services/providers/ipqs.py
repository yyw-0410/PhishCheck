"""IPQualityScore provider for IP reputation and fraud detection."""

from __future__ import annotations

import re
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional, Dict, List, Set

import httpx

from app.core import Settings, get_settings
from app.schemas import IPQSLookup, ParsedEmail
from .base import BaseProvider, is_valid_public_ipv4, is_valid_public_ipv6

logger = logging.getLogger(__name__)

IPQS_BASE_URL = "https://ipqualityscore.com/api/json/ip"


class IPQSProvider(BaseProvider):
    """IPQualityScore API client for IP reputation lookups."""

    def __init__(
        self,
        settings: Optional[Settings] = None,
        *,
        http_client: Optional[httpx.Client] = None,
    ) -> None:
        super().__init__(settings, http_client=http_client)
        self._api_key = self._settings.ipqs_api_key

    # =========================================================================
    # Single IP Lookup
    # =========================================================================

    def lookup_single(self, ip_info: Dict[str, str]) -> IPQSLookup:
        """Query IPQualityScore for a single IP."""
        ip = ip_info.get("ip", "")
        source = ip_info.get("source", "Unknown")
        try:
            url = f"{IPQS_BASE_URL}/{self._api_key}/{ip}"
            params = {
                "strictness": 1,
                "allow_public_access_points": "true",
                "lighter_penalties": "false",
            }
            resp = self._client.get(url, params=params, timeout=httpx.Timeout(10.0, connect=5.0))

            if resp.status_code == 200:
                data = resp.json()
                if data.get("success", False):
                    return IPQSLookup(
                        ip=ip,
                        source=source,
                        fraud_score=data.get("fraud_score"),
                        country_code=data.get("country_code"),
                        city=data.get("city"),
                        isp=data.get("ISP"),
                        is_vpn=data.get("vpn"),
                        is_tor=data.get("tor"),
                        is_proxy=data.get("proxy"),
                        is_bot=data.get("bot_status"),
                        is_crawler=data.get("is_crawler"),
                        recent_abuse=data.get("recent_abuse"),
                        host=data.get("host"),
                    )
                else:
                    return IPQSLookup(ip=ip, source=source, error=data.get("message", "Unknown IPQS error"))
            else:
                return IPQSLookup(ip=ip, source=source, error=f"IPQS API returned status {resp.status_code}")
        except Exception as e:
            return IPQSLookup(ip=ip, source=source, error=f"IPQS lookup failed: {str(e)}")

    # =========================================================================
    # Parallel IP Lookups
    # =========================================================================

    def lookup_parallel(self, ip_list: List[Dict[str, str]]) -> List[IPQSLookup]:
        """Query IPQualityScore for multiple IPs in parallel."""
        results: List[IPQSLookup] = []
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {executor.submit(self.lookup_single, ip_info): ip_info for ip_info in ip_list}
            for future in as_completed(futures):
                try:
                    results.append(future.result(timeout=15))
                except Exception as e:
                    ip_info = futures[future]
                    results.append(IPQSLookup(
                        ip=ip_info.get("ip", ""),
                        source=ip_info.get("source", "Unknown"),
                        error=f"Parallel lookup failed: {str(e)}"
                    ))
        return results

    def lookup_ips(self, ips: List[str]) -> List[IPQSLookup]:
        """Query IPQualityScore for IP reputation (sequential)."""
        results: List[IPQSLookup] = []

        for ip in ips:
            try:
                url = f"{IPQS_BASE_URL}/{self._api_key}/{ip}"
                params = {
                    "strictness": 1,
                    "allow_public_access_points": "true",
                    "lighter_penalties": "false",
                }
                resp = self._client.get(url, params=params)

                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("success", False):
                        results.append(IPQSLookup(
                            ip=ip,
                            fraud_score=data.get("fraud_score"),
                            country_code=data.get("country_code"),
                            city=data.get("city"),
                            isp=data.get("ISP"),
                            is_vpn=data.get("vpn"),
                            is_tor=data.get("tor"),
                            is_proxy=data.get("proxy"),
                            is_bot=data.get("bot_status"),
                            is_crawler=data.get("is_crawler"),
                            recent_abuse=data.get("recent_abuse"),
                            host=data.get("host"),
                        ))
                    else:
                        results.append(IPQSLookup(
                            ip=ip,
                            error=data.get("message", "Unknown IPQS error"),
                        ))
                else:
                    results.append(IPQSLookup(
                        ip=ip,
                        error=f"IPQS API returned status {resp.status_code}",
                    ))
            except Exception as e:
                results.append(IPQSLookup(
                    ip=ip,
                    error=f"IPQS lookup failed: {str(e)}",
                ))

        return results


# =============================================================================
# Email IP Extraction Utility
# =============================================================================

def extract_sender_ips(parsed_email: ParsedEmail) -> List[Dict[str, str]]:
    """Extract IP addresses from Received headers with source context.

    Returns list of dicts with 'ip' and 'source' keys.
    The first IP in Received chain is typically the original sender.
    """
    ips: List[Dict[str, str]] = []
    seen: Set[str] = set()

    # Collect Received headers (they're in reverse order - newest first)
    received_headers = []
    for header in parsed_email.headers:
        if header.name.lower() == "received":
            received_headers.append(header.value or "")

    # Reverse to get chronological order (sender -> recipient)
    received_headers.reverse()

    for idx, value in enumerate(received_headers):
        # Determine source label based on position
        if idx == 0:
            source = "Sender Origin"
        elif idx == len(received_headers) - 1:
            source = "Final Relay"
        else:
            source = f"Mail Relay #{idx}"

        found_ip = False

        # 1. Try IPv4 in brackets: from hostname [1.2.3.4]
        from_bracket_match = re.search(r'from\s+[^\[\]]*\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', value, re.IGNORECASE)
        if from_bracket_match:
            ip = from_bracket_match.group(1)
            if ip not in seen and is_valid_public_ipv4(ip):
                seen.add(ip)
                ips.append({"ip": ip, "source": source})
                found_ip = True

        # 2. Try IPv4 in parentheses
        if not found_ip:
            from_paren_match = re.search(r'from\s+\S+\s+\((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)', value, re.IGNORECASE)
            if from_paren_match:
                ip = from_paren_match.group(1)
                if ip not in seen and is_valid_public_ipv4(ip):
                    seen.add(ip)
                    ips.append({"ip": ip, "source": source})
                    found_ip = True

        # 3. Try IPv6 in brackets
        if not found_ip:
            from_ipv6_match = re.search(r'from\s+[^\[\]]*\[(?:IPv6:)?([0-9a-fA-F:]+)\]', value, re.IGNORECASE)
            if from_ipv6_match:
                ip = from_ipv6_match.group(1)
                if ip not in seen and is_valid_public_ipv6(ip):
                    seen.add(ip)
                    ips.append({"ip": ip, "source": source})
                    found_ip = True

        # 4. Fallback: any IPv4 in brackets
        if not found_ip:
            bracket_match = re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', value)
            if bracket_match:
                ip = bracket_match.group(1)
                if ip not in seen and is_valid_public_ipv4(ip):
                    seen.add(ip)
                    ips.append({"ip": ip, "source": source})
                    found_ip = True

        # 5. Fallback: any IPv4 in parentheses
        if not found_ip:
            paren_match = re.search(r'\((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)', value)
            if paren_match:
                ip = paren_match.group(1)
                if ip not in seen and is_valid_public_ipv4(ip):
                    seen.add(ip)
                    ips.append({"ip": ip, "source": source})
                    found_ip = True

        # 6. Fallback: any IPv6 in brackets
        if not found_ip:
            ipv6_match = re.search(r'\[(?:IPv6:)?([0-9a-fA-F:]+)\]', value, re.IGNORECASE)
            if ipv6_match:
                ip = ipv6_match.group(1)
                if ip not in seen and is_valid_public_ipv6(ip):
                    seen.add(ip)
                    ips.append({"ip": ip, "source": source})

    # Limit to first 5 unique IPs to protect API quota
    return ips[:5]
