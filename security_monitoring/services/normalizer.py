import html
import ipaddress
import re
from urllib.parse import urlparse, urlunparse, unquote
from typing import List, Dict, Any, Tuple



def normalize_ip(value: str) -> str:
    """Normalize IPv4 / IPv6 addresses to standard string format."""
    clean = value.strip()
    try:
        ip_obj = ipaddress.ip_address(clean)
        return str(ip_obj)
    except ValueError:
        return clean.lower()


def normalize_domain(value: str) -> str:
    """Normalize domain name: lowercase, strip trailing dot and whitespace."""
    clean = value.strip().rstrip(".").lower()
    return clean


def normalize_url(value: str) -> str:
    """Normalize URL: lowercase scheme and host, strip standard ports, normalize path."""
    clean = value.strip()
    try:
        parsed = urlparse(clean)
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()

        # Remove standard ports
        if scheme == "http" and netloc.endswith(":80"):
            netloc = netloc[:-3]
        elif scheme == "https" and netloc.endswith(":443"):
            netloc = netloc[:-4]

        # Strip trailing dot from hostname if present
        if ":" in netloc:
            host, port = netloc.split(":", 1)
            netloc = f"{host.rstrip('.')}:{port}"
        else:
            netloc = netloc.rstrip(".")

        path = parsed.path or "/"
        # Avoid duplicate slashes
        while "//" in path:
            path = path.replace("//", "/")

        normalized = urlunparse((
            scheme,
            netloc,
            path,
            parsed.params,
            parsed.query,
            ""  # discard fragment for indicator matching
        ))
        return normalized
    except Exception:
        return clean.lower()


def normalize_hash(value: str) -> str:
    """Normalize hash: strip whitespace and lowercase."""
    return value.strip().lower()


def normalize_payload_pattern(value: str) -> str:
    """Normalize payload pattern: strip and collapse whitespace."""
    clean = " ".join(value.strip().split())
    return clean


def normalize_user_agent(value: str) -> str:
    """Normalize user agent: strip outer whitespace."""
    return value.strip()


def normalize_ioc(ioc_type: str, value: str) -> str:
    """Dispatch normalization based on IOC type."""
    ioc_type = ioc_type.upper()
    if ioc_type == "IP":
        return normalize_ip(value)
    elif ioc_type == "DOMAIN":
        return normalize_domain(value)
    elif ioc_type == "URL":
        return normalize_url(value)
    elif ioc_type == "HASH":
        return normalize_hash(value)
    elif ioc_type == "PAYLOAD_PATTERN":
        return normalize_payload_pattern(value)
    elif ioc_type == "USER_AGENT":
        return normalize_user_agent(value)
    return value.strip()


def normalize_and_deduplicate(raw_iocs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Normalizes a list of raw IOC dicts and deduplicates by (ioc_type, normalized_value).
    Returns list of dicts: {'ioc_type': str, 'value': str, 'normalized_value': str}
    """
    seen: set[Tuple[str, str]] = set()
    deduped = []

    for item in raw_iocs:
        ioc_type = item.get("ioc_type", "").upper()
        raw_val = item.get("value", "")
        if not ioc_type or not raw_val:
            continue

        normalized = normalize_ioc(ioc_type, raw_val)
        key = (ioc_type, normalized)
        if key not in seen:
            seen.add(key)
            deduped.append({
                "ioc_type": ioc_type,
                "value": raw_val,
                "normalized_value": normalized
            })

    return deduped


def normalize_for_inspection(input_str: str) -> str:
    """
    Security normalization stage before signature matching.
    Safely decodes common representations used to disguise suspicious input:
    - Recursive / repeated URL encoding (e.g. %253Cscript%253E -> %3Cscript%3E -> <script>)
    - HTML entities (e.g. &lt; -> <, &#60; -> <, &#x3c; -> <)
    - Unicode & Hex escapes (e.g. \\u003c -> <, \\x3c -> <, \\74 -> <)
    - Backslash escaping (e.g. \\< -> <)
    - Case normalization (.lower())

    CRITICAL: Normalization is for inspection only. The normalized content
    must NEVER be executed or injected into executable contexts.
    """
    if not input_str or not isinstance(input_str, str):
        return ""

    decoded = input_str

    # 1. Multi-pass URL decoding (up to 3 passes to prevent infinite loop or deep nesting)
    for _ in range(3):
        try:
            new_decoded = unquote(decoded)
            if new_decoded == decoded:
                break
            decoded = new_decoded
        except Exception:
            break

    # 2. HTML entity unescaping
    try:
        decoded = html.unescape(decoded)
    except Exception:
        pass

    # 3. Unicode escape sequences (e.g., \\u003c -> <)
    try:
        decoded = re.sub(
            r'\\u([0-9a-fA-F]{4})',
            lambda m: chr(int(m.group(1), 16)),
            decoded
        )
    except Exception:
        pass

    # 4. Hex escape sequences (e.g., \\x3c -> <)
    try:
        decoded = re.sub(
            r'\\x([0-9a-fA-F]{2})',
            lambda m: chr(int(m.group(1), 16)),
            decoded
        )
    except Exception:
        pass

    # 5. Octal escape sequences (e.g., \\74 -> <)
    try:
        decoded = re.sub(
            r'\\([0-7]{1,3})',
            lambda m: chr(int(m.group(1), 8)),
            decoded
        )
    except Exception:
        pass

    # 6. Null bytes and control characters inside tags/words
    decoded = decoded.replace("\x00", "")

    # 7. Case normalization for signature matching
    return decoded.lower()

