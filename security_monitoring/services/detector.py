import json
import re
import ipaddress
from typing import Dict, Any, List, Optional, Tuple
from django.http import HttpRequest

from security_monitoring.services.normalizer import normalize_for_inspection


# Signature Rules Definition for Detection Engine
XSS_DETECTION_RULES = [
    {
        "id": "script_tag_injection",
        "name": "Script Tag Injection",
        "description": "Direct insertion of HTML <script> element",
        "pattern": re.compile(r'<\s*script\b', re.IGNORECASE),
        "confidence_weight": 0.98,
    },
    {
        "id": "html_event_handler",
        "name": "HTML Event Handler Attribute",
        "description": "Inline event handler capable of executing arbitrary script (e.g. onerror=, onload=)",
        "pattern": re.compile(r'\b(?:onerror|onload|onclick|onmouseover|onfocus|onblur|onmouseenter|onsubmit|onchange|onunload|onresize|onloadstart)\s*=', re.IGNORECASE),
        "confidence_weight": 0.95,
    },
    {
        "id": "javascript_pseudo_protocol",
        "name": "JavaScript URI Pseudo-Protocol",
        "description": "javascript: pseudo-protocol in link or resource attribute",
        "pattern": re.compile(r'javascript\s*:', re.IGNORECASE),
        "confidence_weight": 0.96,
    },
    {
        "id": "vbscript_pseudo_protocol",
        "name": "VBScript URI Pseudo-Protocol",
        "description": "vbscript: pseudo-protocol in resource attribute",
        "pattern": re.compile(r'vbscript\s*:', re.IGNORECASE),
        "confidence_weight": 0.94,
    },
    {
        "id": "svg_event_handler",
        "name": "SVG Vector Event Handler",
        "description": "SVG element containing inline event handler execution",
        "pattern": re.compile(r'<\s*svg\b[^>]*?(?:onload|onerror|onmouseover)\s*=', re.IGNORECASE),
        "confidence_weight": 0.96,
    },
    {
        "id": "nested_browsing_injection",
        "name": "Nested Browsing Injection",
        "description": "Embedded frame or active plugin element (iframe/object/embed/applet)",
        "pattern": re.compile(r'<\s*(?:iframe|object|embed|applet|base)\b', re.IGNORECASE),
        "confidence_weight": 0.92,
    },
    {
        "id": "malicious_data_uri",
        "name": "Executable Data URI Scheme",
        "description": "Executable content disguised in base64/inline data URI",
        "pattern": re.compile(r'data:(?:text\/html|image\/svg\+xml|application\/javascript)', re.IGNORECASE),
        "confidence_weight": 0.90,
    },
    {
        "id": "js_execution_function",
        "name": "Direct JS Execution / DOM API",
        "description": "Invocation of JavaScript evaluation or sensitive DOM accessors",
        "pattern": re.compile(r'\b(?:eval|alert|prompt|confirm)\s*\(|document\.(?:cookie|location|domain)|window\.location', re.IGNORECASE),
        "confidence_weight": 0.90,
    },
    {
        "id": "adversary_demo_vector",
        "name": "Known Adversary Stored Injection Marker",
        "description": "Explicit adversary test signature or marker observed in payload",
        "pattern": re.compile(r'DEMO_VIDEO_PAYLOAD', re.IGNORECASE),
        "confidence_weight": 0.98,
    },
]


def evaluate_string_for_threats(raw_value: str, field_name: str = "") -> List[Dict[str, Any]]:
    """
    Evaluates a candidate input string against threat detection rules.
    Runs normalization stage first to safely reveal obfuscated representations,
    then executes signature matching against both normalized and raw representations.
    """
    if not raw_value or not isinstance(raw_value, str):
        return []

    # Security Normalization Stage (for inspection only, never executed)
    normalized_value = normalize_for_inspection(raw_value)

    matches = []
    matched_rule_ids = set()

    for rule in XSS_DETECTION_RULES:
        rule_id = rule["id"]
        pattern = rule["pattern"]

        # Test against normalized representation
        norm_match = pattern.search(normalized_value)
        # Also test against raw representation in case of plain vectors
        raw_match = pattern.search(raw_value)

        match_obj = norm_match or raw_match
        if match_obj and rule_id not in matched_rule_ids:
            matched_rule_ids.add(rule_id)
            matched_str = match_obj.group(0)
            matches.append({
                "rule": rule_id,
                "rule_name": rule["name"],
                "pattern": matched_str,
                "field": field_name,
                "confidence_weight": rule["confidence_weight"],
                "raw_snippet": raw_value[:200]
            })

    return matches


def get_client_ip(request: HttpRequest) -> str:
    """Safely extracts client IP address from HttpRequest."""
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        raw_ip = x_forwarded_for.split(",")[0].strip()
        try:
            ipaddress.ip_address(raw_ip)
            return raw_ip
        except ValueError:
            pass

    remote_addr = request.META.get("REMOTE_ADDR")
    if remote_addr:
        try:
            ipaddress.ip_address(remote_addr)
            return remote_addr
        except ValueError:
            pass

    return "127.0.0.1"


def inspect_request(request: HttpRequest) -> Dict[str, Any]:
    """
    Inspects the actual incoming HTTP request received by Django.
    Does NOT depend on a special field such as 'payload'.
    Inspects:
    - request.GET (all query parameters)
    - request.POST (all form values)
    - request body (raw or JSON parsed)
    - query string
    - relevant request headers (User-Agent, Referer, custom headers)
    - request path & HTTP method

    Returns structured evidence.
    """
    all_matches: List[Dict[str, Any]] = []
    extracted_payload = ""
    primary_inspected_field = ""

    # 1. Inspect request.GET
    for key, val in request.GET.items():
        field_matches = evaluate_string_for_threats(val, field_name=f"GET.{key}")
        if field_matches:
            all_matches.extend(field_matches)
            if not extracted_payload:
                extracted_payload = val
                primary_inspected_field = f"GET.{key}"

    # 2. Inspect request.POST
    for key, val in request.POST.items():
        field_matches = evaluate_string_for_threats(val, field_name=f"POST.{key}")
        if field_matches:
            all_matches.extend(field_matches)
            if not extracted_payload:
                extracted_payload = val
                primary_inspected_field = f"POST.{key}"

    # 3. Inspect raw request body (e.g. JSON or direct text submissions)
    raw_body_str = ""
    try:
        if request.body:
            raw_body_str = request.body.decode("utf-8", errors="replace")
            # If body was JSON, inspect individual values
            try:
                parsed_json = json.loads(raw_body_str)
                if isinstance(parsed_json, dict):
                    for k, v in parsed_json.items():
                        if isinstance(v, str):
                            json_matches = evaluate_string_for_threats(v, field_name=f"JSON.{k}")
                            if json_matches:
                                all_matches.extend(json_matches)
                                if not extracted_payload:
                                    extracted_payload = v
                                    primary_inspected_field = f"JSON.{k}"
            except Exception:
                pass

            # Also inspect full raw body string
            body_matches = evaluate_string_for_threats(raw_body_str, field_name="BODY")
            if body_matches:
                for bm in body_matches:
                    if not any(m["rule"] == bm["rule"] for m in all_matches):
                        all_matches.append(bm)
                if not extracted_payload:
                    extracted_payload = raw_body_str
                    primary_inspected_field = "BODY"
    except Exception:
        pass

    # 4. Inspect QUERY_STRING
    query_string = request.META.get("QUERY_STRING", "")
    if query_string:
        qs_matches = evaluate_string_for_threats(query_string, field_name="QUERY_STRING")
        for qm in qs_matches:
            if not any(m["rule"] == qm["rule"] for m in all_matches):
                all_matches.append(qm)
        if not extracted_payload and qs_matches:
            extracted_payload = query_string
            primary_inspected_field = "QUERY_STRING"

    # 5. Inspect relevant headers
    user_agent = request.META.get("HTTP_USER_AGENT", "")
    relevant_headers = {
        "User-Agent": user_agent,
        "Referer": request.META.get("HTTP_REFERER", ""),
        "Content-Type": request.META.get("CONTENT_TYPE", ""),
        "Accept": request.META.get("HTTP_ACCEPT", ""),
    }
    for h_name, h_val in relevant_headers.items():
        if h_val:
            h_matches = evaluate_string_for_threats(h_val, field_name=f"HEADER.{h_name}")
            if h_matches:
                all_matches.extend(h_matches)
                if not extracted_payload:
                    extracted_payload = h_val
                    primary_inspected_field = f"HEADER.{h_name}"

    detected = len(all_matches) > 0
    confidence = 0.0
    if detected:
        # Calculate combined confidence
        max_weight = max((m.get("confidence_weight", 0.90) for m in all_matches), default=0.90)
        bonus = min(0.08, (len(all_matches) - 1) * 0.03)
        confidence = round(min(0.99, max_weight + bonus), 2)

    source_ip = get_client_ip(request)
    matched_signatures = [m["rule"] for m in all_matches]

    return {
        "detected": detected,
        "attack_type": "stored_xss" if detected else None,
        "confidence": confidence,
        "matches": [
            {
                "rule": m["rule"],
                "pattern": m["pattern"],
                "field": m.get("field", ""),
                "rule_name": m.get("rule_name", ""),
            }
            for m in all_matches
        ],
        "matched_signatures": matched_signatures,
        "extracted_payload": extracted_payload,
        "inspected_field": primary_inspected_field,
        "source_ip": source_ip,
        "user_agent": user_agent,
        "method": request.method,
        "path": request.path,
        "query_string": query_string,
        "headers": relevant_headers,
        "raw_body": raw_body_str,
    }
