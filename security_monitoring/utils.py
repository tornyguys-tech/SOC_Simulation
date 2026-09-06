"""
security_monitoring/utils.py

Authoritative client-IP resolution for ThreatLens.

All security events, incidents, and SOC displays must obtain the client IP
from get_client_ip(request) defined here.  No other module should perform
independent IP resolution.

Design
------
The application may run behind a reverse proxy (e.g. Render) that forwards
the original client address via the X-Forwarded-For header:

    X-Forwarded-For: <client>, <proxy1>, <proxy2>

We trust only the LAST `TRUSTED_PROXY_COUNT` entries in that chain (added by
our own infrastructure). Everything further left was supplied by upstream and
may have been set by the original client. The "real" client IP is the entry
immediately before the trusted proxies start.

Configuration (settings.py / environment)
------------------------------------------
TRUSTED_PROXY_COUNT (int, default 1)
    Number of reverse-proxy hops that Django sits behind.
    - 0 : no proxy; always use REMOTE_ADDR.
    - 1 : one trusted proxy (e.g. Render); take X-Forwarded-For[-1 hops].
    - 2 : two trusted proxies; strip two entries from the right, etc.

Security
--------
A direct internet client cannot control REMOTE_ADDR (it is set by the OS/TCP
layer). When TRUSTED_PROXY_COUNT == 0, we always use REMOTE_ADDR, which makes
IP spoofing impossible.

When TRUSTED_PROXY_COUNT >= 1 we read from X-Forwarded-For, but we count from
the RIGHT (supplied by the trusted proxy we control), not from the left
(supplied by the client). This prevents a client from prepending arbitrary
addresses to spoof the SOC display.
"""

import ipaddress
import logging
from django.conf import settings
from django.http import HttpRequest


logger = logging.getLogger(__name__)


def _is_valid_ip(value: str) -> bool:
    """Returns True if *value* is a valid IPv4 or IPv6 address string."""
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


def get_client_ip(request: HttpRequest) -> str:
    """
    Return the resolved originating client IP address.

    Resolution order
    ----------------
    1. If TRUSTED_PROXY_COUNT == 0, return REMOTE_ADDR (no proxy in front).
    2. If TRUSTED_PROXY_COUNT >= 1 and X-Forwarded-For is present:
       - Split on comma, strip whitespace.
       - Validate each candidate with ipaddress.ip_address().
       - The real client is at index -(TRUSTED_PROXY_COUNT + 1) from the right,
         i.e. the entry just before the trusted proxy chain starts.
         If the list is shorter than expected, take the leftmost valid entry.
    3. Fall back to REMOTE_ADDR.
    4. Fall back to "127.0.0.1" as a last resort.

    IPv4 and IPv6 are both supported.
    """
    trusted_proxy_count: int = getattr(settings, "TRUSTED_PROXY_COUNT", 1)

    remote_addr = (request.META.get("REMOTE_ADDR") or "").strip()
    xff_raw = (request.META.get("HTTP_X_FORWARDED_FOR") or "").strip()

    # Debug logging to aid deployment verification (Section 12)
    logger.debug(
        "IP resolution: REMOTE_ADDR=%s  X_FORWARDED_FOR=%r  TRUSTED_PROXY_COUNT=%s",
        remote_addr,
        xff_raw,
        trusted_proxy_count,
    )

    resolved: str = "127.0.0.1"

    if trusted_proxy_count == 0 or not xff_raw:
        # No trusted proxy configured, or no forwarding header present.
        # Trust REMOTE_ADDR only.
        if _is_valid_ip(remote_addr):
            resolved = remote_addr
    else:
        # Parse the forwarding chain.
        candidates = [c.strip() for c in xff_raw.split(",")]
        valid_candidates = [c for c in candidates if _is_valid_ip(c)]

        if valid_candidates:
            # The client IP sits at the position BEFORE the trusted-proxy tail.
            # index = -(trusted_proxy_count + 1) from the end, clamped to 0.
            idx = max(0, len(valid_candidates) - trusted_proxy_count - 1)
            resolved = valid_candidates[idx]
        else:
            # All candidates in XFF were invalid — fall back to REMOTE_ADDR.
            logger.warning(
                "X-Forwarded-For contained no valid IP candidates (%r); "
                "falling back to REMOTE_ADDR=%s",
                xff_raw,
                remote_addr,
            )
            if _is_valid_ip(remote_addr):
                resolved = remote_addr

    logger.debug("RESOLVED_CLIENT_IP=%s", resolved)
    return resolved
