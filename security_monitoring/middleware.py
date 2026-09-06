from typing import Callable
from django.conf import settings
from django.http import HttpRequest, HttpResponse

from security_monitoring.models import SecurityLabPayload
from security_monitoring.services.detector import inspect_request
from security_monitoring.services.parser import process_security_telemetry


class ThreatLensInspectionMiddleware:
    """
    Automatic security inspection middleware.
    Inspects all incoming application HTTP requests (GET, POST, body, query strings, headers)
    for malicious characteristics. Runs normalization before signature matching.
    Automatically creates telemetry, extracts/enriches IOCs, computes dynamic risk score,
    evaluates Sigma rules, and registers the security incident.
    """

    EXCLUDED_PREFIXES = (
        "/static/",
        "/admin/",
        "/soc/incident/",  # Avoid re-inspecting administrative response actions
    )

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]):
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        if not getattr(settings, "SECURITY_MONITORING_ENABLED", True):
            return self.get_response(request)

        path = request.path or "/"
        # Exclude administrative containment actions and static assets
        if any(path.startswith(prefix) for prefix in self.EXCLUDED_PREFIXES):
            return self.get_response(request)

        # Inspect incoming request automatically
        detection = inspect_request(request)

        if detection.get("detected"):
            extracted_payload = detection.get("extracted_payload", "")
            source_ip = detection.get("source_ip", "127.0.0.1")
            user_agent = detection.get("user_agent", "")
            endpoint = request.path

            # Create server-side active rendering record (multi-session shared state)
            payload_obj = SecurityLabPayload.objects.create(
                payload=extracted_payload,
                label=f"Inbound {detection.get('attack_type', 'Threat')} Submission",
                source_ip=source_ip,
                user_agent=user_agent,
                endpoint=endpoint,
                status="ACTIVE",
            )

            # Pass through automated telemetry processing pipeline
            incident = process_security_telemetry(
                event_type="stored_xss_detected",
                source_ip=source_ip,
                method=request.method,
                path=endpoint,
                user_agent=user_agent,
                payload_text=extracted_payload,
                payload_obj=payload_obj,
                query_string=detection.get("query_string", ""),
                request_headers=detection.get("headers", {}),
                request_body=detection.get("raw_body", ""),
                matched_signatures=detection.get("matched_signatures", []),
                payload_reference=str(payload_obj.id),
                extra_context={
                    "request_source": "automatic_inspection_middleware",
                    "inspected_field": detection.get("inspected_field", ""),
                    "matches": detection.get("matches", []),
                    "rendering_record_id": payload_obj.id,
                },
            )

            # Attach detection details to request for downstream view usage
            request.threatlens_detected = True
            request.threatlens_incident = incident
            request.threatlens_payload = payload_obj

        response = self.get_response(request)

        # Post-view check: if a surveillance request was created during this request, link it
        if getattr(request, "threatlens_detected", False):
            incident = getattr(request, "threatlens_incident", None)
            if incident and not incident.surveillance_request_id:
                from tracker.models import SurveillanceRequest
                extracted_payload = detection.get("extracted_payload", "")
                sr = SurveillanceRequest.objects.filter(
                    faction_id=extracted_payload
                ).order_by("-created_at").first()
                if sr:
                    incident.surveillance_request = sr
                    incident.save(update_fields=["surveillance_request"])

        return response
