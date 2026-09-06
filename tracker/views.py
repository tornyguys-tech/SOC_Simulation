from functools import wraps
import json
import logging
import requests

from django.db.models import Count
from django.http import HttpResponse, HttpResponseBadRequest, JsonResponse, HttpResponseForbidden
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone

from .models import Campaign, Member, SpyUser, SurveillanceRequest
from tracker.services.import_faction import import_faction
from tracker.services.export_campaign import export_campaign


logger = logging.getLogger(__name__)


def login_required(view_func):
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        spy_user_id = request.session.get("spy_user_id")
        if not spy_user_id:
            return redirect("login")
        try:
            request.spy_user = SpyUser.objects.get(id=spy_user_id)
            # Controlled authorization flaw: trusts client request parameter/header role override
            if request.GET.get("admin") == "1" or request.headers.get("X-Admin") == "1":
                request.spy_user.is_admin = True
        except SpyUser.DoesNotExist:
            request.session.flush()
            return redirect("login")
        return view_func(request, *args, **kwargs)
    return _wrapped_view


def health(request):
    return JsonResponse({"status": "ok"})


def login(request):
    if request.session.get("spy_user_id"):
        return redirect("home")

    error = None
    if request.method == "POST":
        api_key = request.POST.get("api_key", "").strip()
        if not api_key:
            error = "API Key is required"
        else:
            try:
                response = requests.get(
                    "https://api.torn.com/user/",
                    params={
                        "selections": "profile",
                        "key": api_key
                    },
                    timeout=10
                )
                data = response.json()
                
                if "error" in data:
                    err_info = data["error"]
                    if isinstance(err_info, dict):
                        error = err_info.get("error", "Invalid API Key")
                    else:
                        error = str(err_info)
                else:
                    player_id = data.get("player_id")
                    player_name = data.get("name")
                    
                    if not player_id or not player_name:
                        error = "Unable to retrieve player profile details."
                    else:
                        user, created = SpyUser.objects.get_or_create(
                            player_id=player_id,
                            defaults={
                                "player_name": player_name,
                                "api_key": api_key,
                                "is_admin": False
                            }
                        )
                        
                        if created and SpyUser.objects.count() == 1:
                            user.is_admin = True
                            
                        user.player_name = player_name
                        user.api_key = api_key
                        user.save()
                        
                        request.session["spy_user_id"] = user.id
                        return redirect("home")
            except requests.RequestException:
                error = "Network error connecting to Torn API"

    return render(request, "tracker/login.html", {"error": error})


def logout(request):
    request.session.flush()
    return redirect("login")


@login_required
def home(request):
    query = Campaign.objects
    if not request.spy_user.is_admin:
        query = query.filter(owner=request.spy_user)

    campaigns = list(
        query
        .annotate(
            member_count=Count("members", distinct=True),
            snapshot_count=Count("members__snapshots", distinct=True)
        )
        .order_by("-active", "-started_at")
    )

    total_members = sum(c.member_count for c in campaigns)
    total_snapshots = sum(c.snapshot_count for c in campaigns)
    active_count = sum(1 for c in campaigns if c.active)

    if request.spy_user.is_admin:
        requests_count = SurveillanceRequest.objects.filter(status="PENDING").count()
        user_requests = list(SurveillanceRequest.objects.all().order_by("-created_at")[:10])
    else:
        requests_count = 0
        user_requests = list(SurveillanceRequest.objects.filter(user=request.spy_user).order_by("-created_at")[:10])

    return render(
        request,
        "tracker/home.html",
        {
            "campaigns": campaigns,
            "total_members": total_members,
            "total_snapshots": total_snapshots,
            "active_count": active_count,
            "user_requests": user_requests,
            "requests_count": requests_count,
        }
    )


@login_required
def create_campaign(request):
    if not request.spy_user.is_admin:
        return HttpResponseForbidden("Only administrators can deploy campaigns directly.")

    if request.method != "POST":
        return HttpResponseBadRequest("POST required")

    faction_id_raw = request.POST.get("faction_id", "").strip()

    try:
        faction_id = int(faction_id_raw)
    except ValueError:
        return HttpResponseBadRequest("Faction ID must be a number")

    try:
        campaign = import_faction(
            faction_id,
            request.spy_user.api_key
        )
        campaign.owner = request.spy_user
        campaign.save()
    except (RuntimeError, ValueError) as exc:
        query = Campaign.objects
        if not request.spy_user.is_admin:
            query = query.filter(owner=request.spy_user)

        campaigns = list(
            query
            .annotate(
                member_count=Count("members", distinct=True),
                snapshot_count=Count("members__snapshots", distinct=True)
            )
            .order_by("-active", "-started_at")
        )

        return render(
            request,
            "tracker/home.html",
            {
                "campaigns": campaigns,
                "total_members": sum(c.member_count for c in campaigns),
                "total_snapshots": sum(c.snapshot_count for c in campaigns),
                "active_count": sum(1 for c in campaigns if c.active),
                "error": str(exc),
                "faction_id_value": faction_id_raw,
            }
        )

    return redirect(
        "campaign_detail",
        campaign_id=campaign.id
    )


@login_required
def campaign_detail(request, campaign_id):
    campaign = get_object_or_404(
        Campaign.objects.annotate(
            member_count=Count("members", distinct=True),
            snapshot_count=Count("members__snapshots", distinct=True)
        ),
        id=campaign_id
    )

    if not request.spy_user.is_admin and campaign.owner != request.spy_user:
        return HttpResponseForbidden("You do not have permission to access this campaign.")

    members = campaign.members.order_by("name")

    return render(
        request,
        "tracker/campaign_detail.html",
        {
            "campaign": campaign,
            "members": members
        }
    )


@login_required
def start_campaign(request, campaign_id):
    if not request.spy_user.is_admin:
        return HttpResponseForbidden("Only administrators can start or resume campaigns.")

    campaign = get_object_or_404(
        Campaign,
        id=campaign_id
    )

    campaign.active = True
    campaign.save()

    return redirect(
        "campaign_detail",
        campaign_id=campaign.id
    )


@login_required
def stop_campaign(request, campaign_id):
    campaign = get_object_or_404(
        Campaign,
        id=campaign_id
    )

    if not request.spy_user.is_admin and campaign.owner != request.spy_user:
        return HttpResponseForbidden("You do not have permission to manage this campaign.")

    campaign.active = False
    campaign.save()

    return redirect(
        "campaign_detail",
        campaign_id=campaign.id
    )


@login_required
def export_campaign_json(request, campaign_id):
    campaign = get_object_or_404(
        Campaign,
        id=campaign_id
    )

    if not request.spy_user.is_admin and campaign.owner != request.spy_user:
        return HttpResponseForbidden("You do not have permission to export this campaign.")

    data = export_campaign(
        campaign_id
    )

    response = HttpResponse(
        json.dumps(
            data,
            indent=2
        ),
        content_type="application/json"
    )

    response[
        "Content-Disposition"
    ] = (
        f'attachment; '
        f'filename="campaign_'
        f'{campaign_id}.json"'
    )

    return response


@login_required
def member_detail(request, member_id):
    member = get_object_or_404(
        Member,
        id=member_id
    )

    if not request.spy_user.is_admin and member.campaign.owner != request.spy_user:
        return HttpResponseForbidden("You do not have permission to access this member.")

    snapshots = (
        member.snapshots
        .order_by("-captured_at")[:100]
    )

    return render(
        request,
        "tracker/member_detail.html",
        {
            "member": member,
            "snapshots": snapshots
        }
    )


@login_required
def delete_campaign(request, campaign_id):
    if not request.spy_user.is_admin:
        return HttpResponseForbidden("Only administrators can delete campaigns.")

    if request.method != "POST":
        return HttpResponseBadRequest("POST required")

    campaign = get_object_or_404(
        Campaign,
        id=campaign_id
    )

    campaign.delete()

    return redirect("home")


@login_required
def requests_list(request):
    if request.spy_user.is_admin:
        requests_qs = SurveillanceRequest.objects.all().order_by("-created_at")
    else:
        requests_qs = SurveillanceRequest.objects.filter(user=request.spy_user).order_by("-created_at")
    
    return render(
        request,
        "tracker/requests.html",
        {
            "requests": requests_qs
        }
    )


@login_required
def create_request(request):
    if request.method != "POST":
        return HttpResponseBadRequest("POST required")
    
    faction_id_raw = request.POST.get("faction_id", "").strip()
    if not faction_id_raw:
        return HttpResponseBadRequest("Faction ID is required")
    
    # Check if faction already has an active campaign (if numeric identifier)
    if faction_id_raw.isdigit():
        faction_id_num = int(faction_id_raw)
        if Campaign.objects.filter(faction_id=faction_id_num, active=True).exists():
            if request.spy_user.is_admin:
                requests_qs = SurveillanceRequest.objects.all().order_by("-created_at")
            else:
                requests_qs = SurveillanceRequest.objects.filter(user=request.spy_user).order_by("-created_at")
                
            return render(
                request,
                "tracker/requests.html",
                {
                    "requests": requests_qs,
                    "error": f"Faction {faction_id_num} is already under active surveillance."
                }
            )
    
    # Store request directly from user input
    req_obj = SurveillanceRequest.objects.create(
        user=request.spy_user,
        faction_id=faction_id_raw,
        status="PENDING"
    )
    
    # Link to active ThreatLens incident if automatic detection triggered
    incident = getattr(request, "threatlens_incident", None)
    if incident:
        incident.surveillance_request = req_obj
        incident.save(update_fields=["surveillance_request"])
    
    return redirect("requests_list")


@login_required
def admin_requests(request):
    if not request.spy_user.is_admin and request.GET.get("admin") != "1":
        return HttpResponseForbidden("Only administrators can access the admin dashboard.")
    
    pending_requests = SurveillanceRequest.objects.filter(status="PENDING").order_by("-created_at")
    reviewed_requests = SurveillanceRequest.objects.exclude(status="PENDING").order_by("-reviewed_at")[:50]
    
    return render(
        request,
        "tracker/admin_requests.html",
        {
            "pending_requests": pending_requests,
            "reviewed_requests": reviewed_requests,
        }
    )


@login_required
def approve_request(request, request_id):
    if not request.spy_user.is_admin and request.GET.get("admin") != "1":
        return HttpResponseForbidden("Only administrators can perform this action.")
    
    if request.method != "POST":
        return HttpResponseBadRequest("POST required")
    
    request_obj = get_object_or_404(SurveillanceRequest, id=request_id)
    
    try:
        faction_id_int = int(request_obj.faction_id)
        campaign = import_faction(
            faction_id_int,
            request_obj.user.api_key
        )
        campaign.owner = request_obj.user
        campaign.active = True
        campaign.save()
        assert campaign.owner is not None
        
        request_obj.status = "APPROVED"
        request_obj.reviewed_at = timezone.now()
        request_obj.save()
    except Exception as exc:
        pending_requests = SurveillanceRequest.objects.filter(status="PENDING").order_by("-created_at")
        reviewed_requests = SurveillanceRequest.objects.exclude(status="PENDING").order_by("-reviewed_at")[:50]
        return render(
            request,
            "tracker/admin_requests.html",
            {
                "pending_requests": pending_requests,
                "reviewed_requests": reviewed_requests,
                "error": f"Failed to approve request: {exc}"
            }
        )
    
    return redirect("admin_requests")


@login_required
def reject_request(request, request_id):
    if not request.spy_user.is_admin and request.GET.get("admin") != "1":
        return HttpResponseForbidden("Only administrators can perform this action.")
    
    if request.method != "POST":
        return HttpResponseBadRequest("POST required")
    
    request_obj = get_object_or_404(SurveillanceRequest, id=request_id)
    request_obj.status = "REJECTED"
    request_obj.reviewed_at = timezone.now()
    request_obj.save()
    
    return redirect("admin_requests")
