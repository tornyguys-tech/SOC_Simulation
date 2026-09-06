from django.contrib import admin
from .models import SecurityLabPayload, SecurityEvent, IOC, SecurityIncident


@admin.register(SecurityLabPayload)
class SecurityLabPayloadAdmin(admin.ModelAdmin):
    list_display = ("id", "label", "status", "source_ip", "created_at")
    list_filter = ("status", "created_at")
    search_fields = ("payload", "label", "source_ip")


@admin.register(SecurityEvent)
class SecurityEventAdmin(admin.ModelAdmin):
    list_display = ("id", "event_type", "source_ip", "method", "path", "created_at")
    list_filter = ("event_type", "method", "created_at")
    search_fields = ("source_ip", "path", "user_agent")


@admin.register(IOC)
class IOCAdmin(admin.ModelAdmin):
    list_display = ("id", "ioc_type", "normalized_value", "reputation", "confidence", "created_at")
    list_filter = ("ioc_type", "reputation", "created_at")
    search_fields = ("value", "normalized_value")


@admin.register(SecurityIncident)
class SecurityIncidentAdmin(admin.ModelAdmin):
    list_display = ("id", "title", "severity", "status", "risk_score", "source_ip", "created_at")
    list_filter = ("severity", "status", "created_at")
    search_fields = ("title", "payload", "source_ip")
