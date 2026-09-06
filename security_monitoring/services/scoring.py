from typing import List, Dict, Any, Tuple, Optional


def calculate_risk_score(
    payload_text: str,
    enriched_iocs: List[Dict[str, Any]],
    user_agent: str,
    event_count_recent: int = 1,
    matched_signatures: Optional[List[str]] = None
) -> Tuple[int, str, List[Dict[str, Any]]]:
    """
    Computes an explainable risk score (0-100), severity level, and breakdown of contributors
    derived directly from the incoming event telemetry.
    """
    score = 0
    breakdown: List[Dict[str, Any]] = []
    matched_signatures = matched_signatures or []

    # 1. Stored XSS payload signatures (+50)
    has_payload_pattern = False
    xss_indicators = ["<script", "onerror=", "onload=", "javascript:", "vbscript:", "<svg", "<iframe", "alert(", "eval("]
    payload_lower = payload_text.lower() if payload_text else ""

    if any(ind in payload_lower for ind in xss_indicators) or "DEMO_VIDEO_PAYLOAD" in (payload_text or "").upper():
        has_payload_pattern = True
    elif any(ioc.get("ioc_type") == "PAYLOAD_PATTERN" for ioc in enriched_iocs):
        has_payload_pattern = True
    elif matched_signatures:
        has_payload_pattern = True

    if has_payload_pattern:
        score += 50
        breakdown.append({
            "rule": "Controlled Stored-XSS Payload Signature",
            "description": "Observed executable HTML/JS script injection or event-handler marker in incoming request",
            "points": 50
        })

    # 1b. Additional vector bonus if multiple attack patterns are detected (+10)
    if len(matched_signatures) > 1:
        score += 10
        sig_str = ", ".join(matched_signatures[:3])
        breakdown.append({
            "rule": "Compound Injection Vectors",
            "description": f"Multiple suspicious attack patterns matched ({sig_str})",
            "points": 10
        })


    # 2. Known malicious IOC (+30)
    malicious_iocs = [
        ioc for ioc in enriched_iocs
        if ioc.get("reputation") == "MALICIOUS"
    ]
    if malicious_iocs:
        score += 30
        names = ", ".join([ioc.get("normalized_value", "") for ioc in malicious_iocs[:2]])
        breakdown.append({
            "rule": "Correlated Malicious Indicators (Threat Feed)",
            "description": f"Matched known adversary intelligence records ({names})",
            "points": 30
        })
    elif any(ioc.get("reputation") == "SUSPICIOUS" for ioc in enriched_iocs):
        score += 15
        breakdown.append({
            "rule": "Suspicious Network / Host Indicator",
            "description": "Correlated with suspicious proxy, relay, or internal test anomaly",
            "points": 15
        })

    # 3. Repeated suspicious events (+10)
    if event_count_recent > 1:
        score += 10
        breakdown.append({
            "rule": "Repeated Telemetry Frequency",
            "description": f"Observed {event_count_recent} recent suspicious events from originating source",
            "points": 10
        })

    # 4. Suspicious user-agent (+10)
    suspicious_ua_tokens = ["curl", "python-requests", "nikto", "sqlmap", "scanner", "test"]
    if user_agent and any(t in user_agent.lower() for t in suspicious_ua_tokens):
        score += 10
        breakdown.append({
            "rule": "Automated Tooling / Script Signature",
            "description": f"Client user-agent matches automated script or tool signature",
            "points": 10
        })

    # Clamp score to 0-100
    score = max(0, min(100, score))

    # Severity Mapping
    if score >= 80:
        severity = "CRITICAL"
    elif score >= 60:
        severity = "HIGH"
    elif score >= 30:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return score, severity, breakdown
