import re
import ipaddress
from urllib.parse import urlparse
from typing import List, Dict, Any


# Regex definitions
IPV4_REGEX = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
URL_REGEX = re.compile(r'https?://[^\s"\'<>]+', re.IGNORECASE)
DOMAIN_REGEX = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b')

MD5_REGEX = re.compile(r'\b[a-fA-F0-9]{32}\b')
SHA1_REGEX = re.compile(r'\b[a-fA-F0-9]{40}\b')
SHA256_REGEX = re.compile(r'\b[a-fA-F0-9]{64}\b')

# Known demo and attack payload patterns
PAYLOAD_PATTERNS = [
    re.compile(r'DEMO_VIDEO_PAYLOAD', re.IGNORECASE),
    re.compile(r'<script[\s\S]*?>[\s\S]*?<\/script>', re.IGNORECASE),
    re.compile(r'onerror\s*=\s*["\']?[^"\'>\s]+', re.IGNORECASE),
    re.compile(r'onload\s*=\s*["\']?[^"\'>\s]+', re.IGNORECASE),
    re.compile(r'javascript:[^\s"\'<>]+', re.IGNORECASE),
]

# Suspicious User-Agent tokens
SUSPICIOUS_UA_TOKENS = [
    "curl", "python-requests", "nikto", "sqlmap", "nmap",
    "gobuster", "wpscan", "burpcollaborator", "metasploit",
    "xss-scanner", "attacker-agent", "headlesschrome"
]


def extract_ips(text: str) -> List[str]:
    """Extract valid IPv4 addresses from text, rejecting invalid octets."""
    if not text:
        return []
    candidates = IPV4_REGEX.findall(text)
    valid_ips = []
    for candidate in candidates:
        try:
            ip_obj = ipaddress.IPv4Address(candidate)
            # Exclude loopback or non-routable in certain contexts if desired, but keep for local demos
            valid_ips.append(str(ip_obj))
        except ipaddress.AddressValueError:
            continue
    return valid_ips


def extract_urls(text: str) -> List[str]:
    """Extract HTTP/HTTPS URLs from text."""
    if not text:
        return []
    urls = URL_REGEX.findall(text)
    cleaned_urls = []
    for u in urls:
        # Strip trailing punctuation if accidentally matched
        u_clean = u.rstrip('.,;:)]}>')
        try:
            parsed = urlparse(u_clean)
            if parsed.scheme in ('http', 'https') and parsed.netloc:
                cleaned_urls.append(u_clean)
        except Exception:
            continue
    return cleaned_urls


def extract_domains(text: str) -> List[str]:
    """Extract domain names from text."""
    if not text:
        return []
    candidates = DOMAIN_REGEX.findall(text)
    valid_domains = []
    # Ignore common image or file extensions that might look like domains in text
    excluded_extensions = {'png', 'jpg', 'jpeg', 'gif', 'svg', 'css', 'js', 'html', 'json', 'txt', 'mp3', 'wav'}
    for dom in candidates:
        parts = dom.split('.')
        tld = parts[-1].lower()
        if tld in excluded_extensions and len(parts) == 2:
            continue
        valid_domains.append(dom)
    return valid_domains


def extract_hashes(text: str) -> List[Dict[str, str]]:
    """Extract MD5, SHA1, and SHA256 hashes from text."""
    if not text:
        return []
    found = []
    # Check SHA256 first
    sha256_matches = set(SHA256_REGEX.findall(text))
    for h in sha256_matches:
        found.append({"hash_type": "SHA256", "value": h.lower()})

    # Check SHA1 (ensuring not substring of SHA256)
    sha1_matches = set(SHA1_REGEX.findall(text))
    for h in sha1_matches:
        if not any(h in s for s in sha256_matches):
            found.append({"hash_type": "SHA1", "value": h.lower()})

    # Check MD5 (ensuring not substring of SHA1/SHA256)
    md5_matches = set(MD5_REGEX.findall(text))
    for h in md5_matches:
        if not any(h in s for s in sha256_matches) and not any(h in s for s in sha1_matches):
            found.append({"hash_type": "MD5", "value": h.lower()})

    return found


def extract_payload_patterns(text: str) -> List[str]:
    """Detect known attack or demo payload signatures."""
    if not text:
        return []
    patterns_found = []
    for pat in PAYLOAD_PATTERNS:
        match = pat.search(text)
        if match:
            patterns_found.append(match.group(0))
    return patterns_found


def inspect_user_agent(user_agent: str) -> Dict[str, Any]:
    """Check if the user-agent matches automated scanning or demo attack patterns."""
    if not user_agent:
        return {"is_suspicious": False, "matched_tokens": []}
    
    ua_lower = user_agent.lower()
    matched = [token for token in SUSPICIOUS_UA_TOKENS if token in ua_lower]
    return {
        "is_suspicious": len(matched) > 0,
        "matched_tokens": matched,
        "user_agent": user_agent
    }


def extract_all_iocs(event_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Extracts all indicator candidates from an event dictionary.
    Returns list of raw IOC dicts: {'ioc_type': str, 'value': str}
    """
    results = []

    # Text corpus to scan
    search_fields = [
        event_data.get("source_ip", ""),
        event_data.get("payload", ""),
        event_data.get("path", ""),
        str(event_data.get("raw_event", "")),
        str(event_data.get("method", ""))
    ]
    combined_text = " \n ".join([s for s in search_fields if s])

    # 1. Source IP directly
    src_ip = event_data.get("source_ip")
    if src_ip:
        for ip in extract_ips(src_ip):
            results.append({"ioc_type": "IP", "value": ip})

    # 2. Extract IPs in payload/corpus
    for ip in extract_ips(combined_text):
        results.append({"ioc_type": "IP", "value": ip})

    # 3. Extract URLs
    for url in extract_urls(combined_text):
        results.append({"ioc_type": "URL", "value": url})
        # Also extract domain from the URL
        try:
            parsed = urlparse(url)
            if parsed.hostname:
                results.append({"ioc_type": "DOMAIN", "value": parsed.hostname})
        except Exception:
            pass

    # 4. Extract standalone Domains
    for domain in extract_domains(combined_text):
        results.append({"ioc_type": "DOMAIN", "value": domain})

    # 5. Extract Hashes
    for h in extract_hashes(combined_text):
        results.append({"ioc_type": "HASH", "value": h["value"]})

    # 6. Extract Payload Patterns
    payload_text = event_data.get("payload", "") or combined_text
    for pat in extract_payload_patterns(payload_text):
        results.append({"ioc_type": "PAYLOAD_PATTERN", "value": pat})

    # 7. Contextual User-Agent
    ua = event_data.get("user_agent", "")
    ua_info = inspect_user_agent(ua)
    if ua_info["is_suspicious"]:
        results.append({"ioc_type": "USER_AGENT", "value": ua})

    return results
