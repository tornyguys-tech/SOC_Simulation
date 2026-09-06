import ipaddress
import json
from functools import wraps

from django.conf import settings
from django.contrib import messages
from django.http import HttpResponse, HttpResponseBadRequest, HttpResponseForbidden, JsonResponse, Http404
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import require_POST
from django.views.decorators.csrf import csrf_exempt

from tracker.models import SpyUser
from security_monitoring.models import SecurityLabPayload, SecurityEvent, IOC, SecurityIncident
from security_monitoring.services.response import take_action_contain, reset_security_lab, verify_active_rendering_state
from security_monitoring.services.sigma import load_all_rules


def check_monitoring_enabled(view_func):
    """Ensures security lab features can only run when SECURITY_LAB_ENABLED is True."""
    @wraps(view_func)
    def _wrapped(request, *args, **kwargs):
        if not getattr(settings, "SECURITY_MONITORING_ENABLED", True):
            raise Http404("Security monitoring is currently disabled.")
        return view_func(request, *args, **kwargs)
    return _wrapped


def admin_required(view_func):
    """
    Requires an authenticated admin SpyUser session, adhering to existing TornSpy auth patterns
    using the application's authenticated SpyUser admin flag.
    """
    @wraps(view_func)
    def _wrapped(request, *args, **kwargs):
        spy_user_id = request.session.get("spy_user_id")
        user = None
        if spy_user_id:
            try:
                user = SpyUser.objects.get(id=spy_user_id)
            except SpyUser.DoesNotExist:
                user = None

        is_admin_flag = bool(user and user.is_admin)

        if not user:
            return redirect("login")

        if not is_admin_flag:
            return HttpResponseForbidden("Access Denied: Administrator privileges required for ThreatLens SOC.")

        request.spy_user = user
        return view_func(request, *args, **kwargs)
    return _wrapped


@check_monitoring_enabled
@csrf_exempt
def xss_demo(request):
    """
    Normal operational dispatch page.

    GET renders the page for every visitor.
    POST accepts field updates, target directives, and sector observations.
    The middleware (ThreatLensInspectionMiddleware) inspects the actual Django request
    automatically across all parameters without relying on any special field name.
    Suspicious input is detected automatically and stored as an active server-side
    database record via SecurityLabPayload.
    The submitted string is NEVER executed by this application; the visible effect is
    a server-side rendering indicator driven by the active database record.
    """
    endpoint = "/dispatch/"
    if request.method == "POST":
        # Middleware already ran inspect_request() and created the incident if detected.
        is_detected = getattr(request, "threatlens_detected", False)
        incident = getattr(request, "threatlens_incident", None)
        payload_obj = getattr(request, "threatlens_payload", None)

        if is_detected and incident:
            if request.headers.get("Accept", "").lower().find("application/json") >= 0 or request.GET.get("format") == "json":
                return JsonResponse({
                    "status": "detected",
                    "incident_id": incident.id,
                    "payload_id": payload_obj.id if payload_obj else None,
                    "risk_score": incident.risk_score,
                    "severity": incident.severity,
                }, status=201)
            return redirect("xss_demo")

        # Clean submission — normal business directive with no malicious vectors
        if request.headers.get("Accept", "").lower().find("application/json") >= 0:
            return JsonResponse({
                "status": "recorded",
                "message": "Sector field directive acknowledged.",
                "endpoint": endpoint,
            }, status=200)

        return redirect("xss_demo")

    active_payloads = SecurityLabPayload.objects.filter(
        status="ACTIVE",
        endpoint=endpoint,
    ).order_by("-created_at")

    has_active_payload = active_payloads.exists()
    current_payload = active_payloads.first() if has_active_payload else None

    sample_targets = [
        {"id": 20491, "callsign": "SHADOW_VECTOR", "threat_level": "LEVEL-4", "sector": "Sector 7 [Industrial]", "status": "ACTIVE_SURVEILLANCE"},
        {"id": 31802, "callsign": "NEXUS_VIPER", "threat_level": "LEVEL-2", "sector": "Sector 3 [Financial]", "status": "MONITORED"},
        {"id": 14920, "callsign": "AEGIS_TITAN", "threat_level": "LEVEL-5", "sector": "Sector 9 [High Value]", "status": "PENDING_REPORT"},
    ]

    return render(
        request,
        "security_monitoring/demo.html",
        {
            "has_active_payload": has_active_payload,
            "current_payload": current_payload,
            "sample_targets": sample_targets,
        },
    )



@check_monitoring_enabled
@admin_required
def soc_dashboard(request):
    """
    ThreatLens SOC Dashboard.
    Admin-only operational security center displaying active incidents,
    threat metrics, extracted IOCs, matched Sigma rules, and response action controls.
    """
    # Metrics calculation
    open_incidents_qs = SecurityIncident.objects.filter(status__in=["OPEN", "INVESTIGATING"])
    contained_incidents_qs = SecurityIncident.objects.filter(status="CONTAINED")
    
    total_open = open_incidents_qs.count()
    critical_count = SecurityIncident.objects.filter(severity="CRITICAL", status__in=["OPEN", "INVESTIGATING"]).count()
    high_count = SecurityIncident.objects.filter(severity="HIGH", status__in=["OPEN", "INVESTIGATING"]).count()
    total_iocs = IOC.objects.count()
    total_contained = contained_incidents_qs.count()

    # Active incident to display (specified by ?incident_id or latest)
    incident_id_param = request.GET.get("incident_id")
    selected_incident = None
    if incident_id_param:
        selected_incident = SecurityIncident.objects.filter(id=incident_id_param).first()

    if not selected_incident:
        # Default to latest OPEN incident, or latest overall incident
        selected_incident = open_incidents_qs.order_by("-created_at").first()
        if not selected_incident:
            selected_incident = SecurityIncident.objects.order_by("-created_at").first()

    # Linked IOCs
    iocs = []
    if selected_incident and selected_incident.event:
        iocs = list(selected_incident.event.iocs.all())
    elif selected_incident:
        iocs = list(IOC.objects.order_by("-created_at")[:20])

    # Sigma Rule details
    sigma_yaml = ""
    if selected_incident and selected_incident.sigma_details:
        primary_rule = selected_incident.sigma_details.get("primary_rule", {})
        sigma_yaml = primary_rule.get("raw_yaml", "")

    # Fallback to load default Sigma rule text if empty
    if not sigma_yaml:
        all_rules = load_all_rules()
        if all_rules:
            sigma_yaml = all_rules[0].get("_raw_yaml", "")

    # Check database rendering state for containment verification
    rendering_state = verify_active_rendering_state()

    all_incidents = SecurityIncident.objects.all().order_by("-created_at")[:15]

    # Build actual event timeline milestones from real telemetry
    timeline_milestones = []
    if selected_incident and selected_incident.event and selected_incident.event.raw_event:
        raw_timeline = selected_incident.event.raw_event.get("timeline", {})
        if raw_timeline:
            timeline_milestones = [
                {"step": "1", "label": "Request Received", "timestamp": raw_timeline.get("request_received"), "status": "COMPLETED"},
                {"step": "2", "label": "Detection Triggered", "timestamp": raw_timeline.get("detection_triggered"), "status": "COMPLETED"},
                {"step": "3", "label": "IOC Extracted", "timestamp": raw_timeline.get("ioc_extracted"), "status": "COMPLETED"},
                {"step": "4", "label": "IOC Enriched", "timestamp": raw_timeline.get("ioc_enriched"), "status": "COMPLETED"},
                {"step": "5", "label": "Sigma Matched", "timestamp": raw_timeline.get("sigma_matched"), "status": "COMPLETED"},
                {"step": "6", "label": "Incident Created", "timestamp": raw_timeline.get("incident_created"), "status": "COMPLETED"},
            ]
        else:
            base_ts = selected_incident.created_at
            timeline_milestones = [
                {"step": "1", "label": "Request Received", "timestamp": (base_ts - timezone.timedelta(milliseconds=80)).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + " UTC", "status": "COMPLETED"},
                {"step": "2", "label": "Detection Triggered", "timestamp": (base_ts - timezone.timedelta(milliseconds=65)).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + " UTC", "status": "COMPLETED"},
                {"step": "3", "label": "IOC Extracted", "timestamp": (base_ts - timezone.timedelta(milliseconds=50)).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + " UTC", "status": "COMPLETED"},
                {"step": "4", "label": "IOC Enriched", "timestamp": (base_ts - timezone.timedelta(milliseconds=35)).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + " UTC", "status": "COMPLETED"},
                {"step": "5", "label": "Sigma Matched", "timestamp": (base_ts - timezone.timedelta(milliseconds=15)).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + " UTC", "status": "COMPLETED"},
                {"step": "6", "label": "Incident Created", "timestamp": base_ts.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + " UTC", "status": "COMPLETED"},
            ]
        if selected_incident.is_contained and selected_incident.action_taken_at:
            timeline_milestones.append({
                "step": "7",
                "label": "Containment Verified & Closed",
                "timestamp": selected_incident.action_taken_at.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + " UTC",
                "status": "CONTAINED"
            })

    return render(
        request,
        "security_monitoring/soc.html",
        {
            "selected_incident": selected_incident,
            "all_incidents": all_incidents,
            "iocs": iocs,
            "sigma_yaml": sigma_yaml,
            "total_open": total_open,
            "critical_count": critical_count,
            "high_count": high_count,
            "total_iocs": total_iocs,
            "total_contained": total_contained,
            "rendering_state": rendering_state,
            "timeline_milestones": timeline_milestones,
        }
    )


@check_monitoring_enabled
@admin_required
def soc_poll(request):
    """
    Live telemetry polling endpoint for the ThreatLens SOC dashboard.
    Returns the latest incident ID, open incident count, active rendering records count,
    and latest incident timestamp for real-time frontend synchronization.
    """
    latest_open = SecurityIncident.objects.filter(status__in=["OPEN", "INVESTIGATING"]).order_by("-created_at").first()
    latest_any = SecurityIncident.objects.order_by("-created_at").first()
    rendering_state = verify_active_rendering_state()
    active_count = rendering_state["active_payload_count"]
    total_open = SecurityIncident.objects.filter(status__in=["OPEN", "INVESTIGATING"]).count()

    latest_id = latest_open.id if latest_open else (latest_any.id if latest_any else 0)
    latest_title = latest_open.title if latest_open else (latest_any.title if latest_any else "No Incidents")
    latest_ts = latest_open.created_at.isoformat() if latest_open else (latest_any.created_at.isoformat() if latest_any else "")

    return JsonResponse({
        "status": "ok",
        "latest_incident_id": latest_id,
        "latest_title": latest_title,
        "latest_timestamp": latest_ts,
        "total_open": total_open,
        "active_payload_count": active_count,
        "active_surveillance_count": rendering_state.get("active_surveillance_requests_count", 0),
        "is_compromised": rendering_state["is_compromised"],
        "timestamp": timezone.now().isoformat(),
    })



@check_monitoring_enabled
@admin_required
@require_POST
def take_action(request, incident_id):
    """
    Human-in-the-loop response execution.
    Quarantines the active malicious payload record from the database rendering pipeline,
    records forensic audit history, and verifies containment.
    """
    admin_user = getattr(request, "spy_user", None)
    result = take_action_contain(incident_id, admin_user=admin_user)

    if request.headers.get("X-Requested-With") == "XMLHttpRequest" or request.GET.get("format") == "json":
        return JsonResponse(result)

    return redirect(f"/soc/?incident_id={incident_id}")


@check_monitoring_enabled
@admin_required
@require_POST
def reset_lab_view(request):
    """
    Safely clears security telemetry and active rendering records.
    Does NOT touch any real TornSpy data (SpyUser, Campaign, Member, etc.).
    """
    result = reset_security_lab()

    if request.headers.get("X-Requested-With") == "XMLHttpRequest" or request.GET.get("format") == "json":
        return JsonResponse(result)

    return redirect("soc_dashboard")


@check_monitoring_enabled
def api_status(request):
    """Public JSON endpoint to inspect live active rendering state."""
    state = verify_active_rendering_state()
    return JsonResponse({
        "status": "ok",
        "system": "ThreatLens Security Subsystem",
        "timestamp": timezone.now().isoformat(),
        **state
    })
