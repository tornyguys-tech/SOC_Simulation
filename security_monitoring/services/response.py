from django.utils import timezone
from typing import Dict, Any, Optional, List

from security_monitoring.models import SecurityIncident, SecurityLabPayload, SecurityEvent, IOC


def get_active_malicious_surveillance_requests() -> List[Any]:
    """
    Returns SurveillanceRequest records that are still linked to open (non-contained)
    SecurityIncidents. These are the exact records that were associated with a detected
    incident via foreign key — no fuzzy payload pattern scanning.
    """
    from tracker.models import SurveillanceRequest

    linked_ids = list(
        SecurityIncident.objects.filter(
            status__in=["OPEN", "INVESTIGATING"],
            surveillance_request__isnull=False,
        ).values_list("surveillance_request_id", flat=True)
    )
    if not linked_ids:
        return []
    return list(SurveillanceRequest.objects.filter(id__in=linked_ids))


def verify_active_rendering_state() -> Dict[str, Any]:
    """
    Checks if any active payload is currently permitted to render in the database.
    A payload CANNOT be considered deactivated while an active rendering record
    remains in either SecurityLabPayload OR SurveillanceRequest!
    """
    active_payloads = list(SecurityLabPayload.objects.filter(status="ACTIVE"))
    malicious_requests = get_active_malicious_surveillance_requests()

    total_active_count = len(active_payloads) + len(malicious_requests)
    is_compromised = total_active_count > 0

    return {
        "is_compromised": is_compromised,
        "active_payload_count": total_active_count,
        "active_lab_payloads_count": len(active_payloads),
        "active_surveillance_requests_count": len(malicious_requests),
        "active_payloads": [
            {
                "id": p.id,
                "label": p.label,
                "payload": p.payload,
                "endpoint": p.endpoint,
                "created_at": p.created_at.isoformat()
            }
            for p in active_payloads
        ],
        "active_surveillance_requests": [
            {
                "id": sr.id,
                "user": sr.user.player_name if sr.user else "Unknown",
                "player_id": sr.user.player_id if sr.user else "",
                "faction_id": sr.faction_id,
                "status": sr.status,
                "created_at": sr.created_at.isoformat()
            }
            for sr in malicious_requests
        ]
    }


def take_action_contain(incident_id: int, admin_user: Optional[Any] = None) -> Dict[str, Any]:
    """
    Human-in-the-loop containment.

    Deletes ONLY the exact SurveillanceRequest and SecurityLabPayload that are
    directly associated with this incident via foreign key.
    No fuzzy search or broad deletion of unrelated records.
    The incident keeps the captured payload as forensic evidence.
    """
    from tracker.models import SurveillanceRequest

    try:
        incident = SecurityIncident.objects.select_related("payload_record", "surveillance_request").get(id=incident_id)
    except SecurityIncident.DoesNotExist:
        return {"success": False, "error": f"SecurityIncident #{incident_id} not found."}

    # Verify real database rendering state
    rendering_state = verify_active_rendering_state()

    # Idempotent check: only if incident is marked CONTAINED AND no active payloads remain
    if incident.status == "CONTAINED" and not rendering_state["is_compromised"]:
        return {
            "success": True,
            "idempotent": True,
            "message": f"Incident #{incident_id} is already contained and verified clean.",
            "incident_id": incident.id,
            "status": "CONTAINED",
            "active_payloads_count": 0,
            "containment_verified": True,
        }

    deleted_payloads_count = 0
    deleted_surveillance_count = 0

    # Preserve forensic payload text on incident before deletion
    if not incident.payload:
        if incident.payload_record:
            incident.payload = incident.payload_record.payload
        elif incident.surveillance_request:
            incident.payload = incident.surveillance_request.faction_id

    # Preserve the IDs before nulling the FK references in memory
    target_payload_id = incident.payload_record_id
    target_surveillance_id = incident.surveillance_request_id

    # Store the SurveillanceRequest ID for the action_result message before we disconnect it
    surveillance_record_label = (
        f"SurveillanceRequest #{target_surveillance_id}"
        if target_surveillance_id
        else "None"
    )

    # Disconnect FK references in memory BEFORE deleting rows to prevent IntegrityError
    incident.payload_record = None
    incident.payload_record_id = None
    incident.surveillance_request = None
    incident.surveillance_request_id = None

    # 1. Delete ONLY the exact SecurityLabPayload linked to this incident
    if target_payload_id:
        cnt, _ = SecurityLabPayload.objects.filter(id=target_payload_id).delete()
        deleted_payloads_count += cnt

    # 2. Delete ONLY the exact SurveillanceRequest linked to this incident
    if target_surveillance_id:
        cnt, _ = SurveillanceRequest.objects.filter(id=target_surveillance_id).delete()
        deleted_surveillance_count += cnt

    # Verify containment against updated database state
    rendering_state = verify_active_rendering_state()
    verified = not rendering_state["is_compromised"]
    payload_active_str = "NO" if verified else "YES"
    record_status_str = "NOT FOUND" if verified else f"{rendering_state['active_payload_count']} ACTIVE"
    containment_str = "VERIFIED" if verified else "FAILED"

    now = timezone.now()
    incident.status = "CONTAINED"
    incident.reviewed_at = incident.reviewed_at or now
    incident.action_taken_at = now
    incident.action_taken_by = admin_user
    incident.containment_verified = verified
    incident.action_result = (
        f"Action: Delete malicious request | "
        f"Record: {surveillance_record_label} | "
        f"Result: {'SUCCESS' if deleted_surveillance_count > 0 or deleted_payloads_count > 0 else 'NO_RECORD_FOUND'} | "
        f"Verification: {containment_str} | "
        f"Payload active: {payload_active_str} | "
        f"Active rendering record: {record_status_str} | "
        f"Containment: {containment_str}. "
        f"Executed by {getattr(admin_user, 'player_name', 'ADMIN')} at {now.strftime('%Y-%m-%d %H:%M:%S')} UTC. "
        f"Deleted {deleted_payloads_count} SecurityLabPayload(s) and {deleted_surveillance_count} SurveillanceRequest(s) from database. Forensic evidence retained."
    )
    incident.save()

    return {
        "success": True,
        "incident_id": incident.id,
        "status": incident.status,
        "payload_active": payload_active_str,
        "active_rendering_record": record_status_str,
        "containment_verified": verified,
        "payloads_deleted": deleted_payloads_count,
        "surveillance_requests_deleted": deleted_surveillance_count,
        "active_payloads_count": rendering_state["active_payload_count"],
        "message": f"Payload active: {payload_active_str} | Active rendering record: {record_status_str} | Containment: {containment_str}",
    }


def reset_security_lab() -> Dict[str, Any]:
    """
    Safely cleans up security telemetry and rendering records.
    Deletes only SurveillanceRequests that are (or were) linked to security incidents.
    Never touches legitimate TornSpy records that have no security incident association.
    """
    from tracker.models import SurveillanceRequest

    # Collect all SurveillanceRequest IDs referenced by any incident before deletion
    linked_sr_ids = list(
        SecurityIncident.objects.filter(surveillance_request__isnull=False)
        .values_list("surveillance_request_id", flat=True)
    )

    incidents_deleted, _ = SecurityIncident.objects.all().delete()
    iocs_deleted, _ = IOC.objects.all().delete()
    events_deleted, _ = SecurityEvent.objects.all().delete()
    payloads_deleted, _ = SecurityLabPayload.objects.all().delete()

    # Delete only SurveillanceRequests that were linked to incidents
    sr_deleted = 0
    if linked_sr_ids:
        cnt, _ = SurveillanceRequest.objects.filter(id__in=linked_sr_ids).delete()
        sr_deleted = cnt

    return {
        "success": True,
        "message": "Security telemetry cleared to clean state.",
        "records_cleared": {
            "incidents": incidents_deleted,
            "iocs": iocs_deleted,
            "events": events_deleted,
            "payloads": payloads_deleted,
            "malicious_surveillance_requests": sr_deleted,
        }
    }
