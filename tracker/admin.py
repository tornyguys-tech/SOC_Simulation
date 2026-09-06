from django.contrib import admin
from django.utils import timezone
from .models import Campaign, Member, Snapshot, SpyUser, SurveillanceRequest
from tracker.services.import_faction import import_faction


@admin.action(description="Approve selected surveillance requests")
def approve_selected_requests(modeladmin, request, queryset):
    for request_obj in queryset.filter(status="PENDING"):
        try:
            campaign = import_faction(
                request_obj.faction_id,
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
            modeladmin.message_user(
                request,
                f"Error approving request for faction {request_obj.faction_id}: {exc}",
                level='ERROR'
            )


@admin.action(description="Reject selected surveillance requests")
def reject_selected_requests(modeladmin, request, queryset):
    queryset.filter(status="PENDING").update(
        status="REJECTED",
        reviewed_at=timezone.now()
    )


class SurveillanceRequestAdmin(admin.ModelAdmin):
    list_display = ("user", "faction_id", "status", "created_at", "reviewed_at")
    list_filter = ("status", "created_at")
    actions = [approve_selected_requests, reject_selected_requests]


class SpyUserAdmin(admin.ModelAdmin):
    list_display = ("player_name", "player_id", "is_admin", "created_at")
    search_fields = ("player_name", "player_id")


class CampaignAdmin(admin.ModelAdmin):
    list_display = ("faction_name", "faction_id", "owner", "active", "last_scan_at", "last_scan_error")
    list_filter = ("active", "last_scan_at")
    search_fields = ("faction_name", "faction_id")


admin.site.unregister(Campaign) if admin.site.is_registered(Campaign) else None
admin.site.unregister(Member) if admin.site.is_registered(Member) else None
admin.site.unregister(Snapshot) if admin.site.is_registered(Snapshot) else None

admin.site.register(Campaign, CampaignAdmin)
admin.site.register(Member)
admin.site.register(Snapshot)
admin.site.register(SpyUser, SpyUserAdmin)
admin.site.register(SurveillanceRequest, SurveillanceRequestAdmin)