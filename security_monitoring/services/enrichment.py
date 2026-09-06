from typing import Dict, Any


# Deterministic Local Threat Intelligence Knowledgebase
LOCAL_THREAT_INTELLIGENCE: Dict[str, Dict[str, Any]] = {
    # Locally known indicators
    "203.0.113.50": {
        "type": "IP",
        "reputation": "MALICIOUS",
        "confidence": 92,
        "source": "ThreatLens Local Threat Intelligence",
        "asn": "AS64496 - Documentation Network",
        "country": "RU",
        "threat_actor": "APT-CYBERLENS-01",
        "description": "Known malicious source associated with stored-injection activity.",
        "tags": ["c2", "stored-xss", "adversary-staging"]
    },
    "198.51.100.23": {
        "type": "IP",
        "reputation": "SUSPICIOUS",
        "confidence": 75,
        "source": "ThreatLens Local Threat Feed",
        "asn": "AS64497 - Tor Exit Node / Proxy Relay",
        "country": "NL (Simulated)",
        "threat_actor": "UNKNOWN_PROXY",
        "description": "Observed in automated vulnerability probe sweeps.",
        "tags": ["scanner", "proxy"]
    },
    "127.0.0.1": {
        "type": "IP",
        "reputation": "SUSPICIOUS",
        "confidence": 60,
        "source": "Local System Loopback (Simulated Threat Origin)",
        "asn": "Localhost / Internal Test Bench",
        "country": "INTERNAL",
        "threat_actor": "LOCAL_OPERATOR_SIMULATION",
        "description": "Direct local submission of controlled test payload.",
        "tags": ["local-test", "operator-origin"]
    },

    # Known malicious domains
    "malicious-payload.demo": {
        "type": "DOMAIN",
        "reputation": "MALICIOUS",
        "confidence": 88,
        "source": "ThreatLens Domain Guard",
        "registrar": "Local Threat Intelligence",
        "threat_actor": "APT-CYBERLENS-01",
        "description": "Domain associated with malicious content delivery.",
        "tags": ["phishing", "stored-xss-delivery"]
    },
    "evil-cdn.example.org": {
        "type": "DOMAIN",
        "reputation": "MALICIOUS",
        "confidence": 85,
        "source": "ThreatLens Domain Guard",
        "threat_actor": "DEMO_EXPLOIT_KIT",
        "description": "Simulated hostile content delivery network.",
        "tags": ["asset-hosting"]
    },

    # Known malicious URLs
    "http://malicious-payload.demo/exploit.js": {
        "type": "URL",
        "reputation": "MALICIOUS",
        "confidence": 95,
        "source": "ThreatLens URL Intelligence",
        "threat_actor": "APT-CYBERLENS-01",
        "description": "URI associated with malicious script delivery.",
        "tags": ["malicious-script"]
    },

    # Payload signatures
    "DEMO_VIDEO_PAYLOAD": {
        "type": "PAYLOAD_PATTERN",
        "reputation": "MALICIOUS",
        "confidence": 98,
        "source": "ThreatLens Detection Signatures",
        "threat_actor": "UNKNOWN",
        "description": "Confirmed stored-XSS detection signature.",
        "tags": ["stored-xss", "high-impact-vector"]
    },

    # Reference hashes
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": {
        "type": "HASH",
        "reputation": "CLEAN",
        "confidence": 100,
        "source": "NIST Hash Database",
        "description": "Standard SHA-256 for empty file.",
        "tags": ["known-hash"]
    },
    "5d41402abc4b2a76b9719d911017c592": {
        "type": "HASH",
        "reputation": "SUSPICIOUS",
        "confidence": 70,
        "source": "ThreatLens Hash Repository",
        "description": "MD5 of common test string 'hello'.",
        "tags": ["test-hash"]
    }
}


def enrich_indicator(ioc_type: str, normalized_value: str) -> Dict[str, Any]:
    """
    Looks up the normalized indicator in the local threat intelligence database.
    Returns dictionary with reputation, confidence, and enrichment metadata.
    """
    # Exact lookup
    if normalized_value in LOCAL_THREAT_INTELLIGENCE:
        data = LOCAL_THREAT_INTELLIGENCE[normalized_value]
        return {
            "reputation": data.get("reputation", "UNKNOWN"),
            "confidence": data.get("confidence", 80),
            "enrichment": {
                "source": data.get("source", "ThreatLens Intelligence"),
                "status": "Enriched",
                "asn": data.get("asn", "N/A"),
                "country": data.get("country", "N/A"),
                "threat_actor": data.get("threat_actor", "N/A"),
                "description": data.get("description", ""),
                "tags": data.get("tags", []),
            }
        }

    # Pattern check for payload patterns
    if ioc_type == "PAYLOAD_PATTERN" and "DEMO_VIDEO_PAYLOAD" in normalized_value.upper():
        data = LOCAL_THREAT_INTELLIGENCE["DEMO_VIDEO_PAYLOAD"]
        return {
            "reputation": data["reputation"],
            "confidence": data["confidence"],
            "enrichment": {
                "source": data["source"],
                "status": "Enriched",
                "threat_actor": data["threat_actor"],
                "description": data["description"],
                "tags": data["tags"]
            }
        }

    # Suspicious User Agent enrichment
    if ioc_type == "USER_AGENT":
        return {
            "reputation": "SUSPICIOUS",
            "confidence": 65,
            "enrichment": {
                "source": "ThreatLens Behavioral Heuristics",
                "status": "Enriched",
                "category": "Automated Tooling / Script",
                "description": "User-agent matches automated scanning or non-browser client signatures.",
                "tags": ["script", "scanner"]
            }
        }

    # Generic / Unknown Indicator
    return {
        "reputation": "UNKNOWN",
        "confidence": 15,
        "enrichment": {
            "source": "ThreatLens Local Feed (No record found)",
            "status": "Observed Only",
            "category": "Unclassified",
            "description": "No prior adverse reports in local intelligence feed.",
            "tags": ["unclassified"]
        }
    }
