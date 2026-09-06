from django.db import models
from django.utils import timezone


class SecurityLabPayload(models.Model):
    STATUS_CHOICES = [
        ("ACTIVE", "Active"),
        ("QUARANTINED", "Quarantined"),
        ("REMOVED", "Removed"),
    ]

    payload = models.TextField(help_text="Controlled payload content or token")
    label = models.CharField(max_length=255, blank=True, default="Stored XSS Vector")
    source_ip = models.CharField(max_length=64, blank=True, default="127.0.0.1")
    user_agent = models.TextField(blank=True, default="")
    endpoint = models.CharField(max_length=255, blank=True, default="/dispatch/")
    status = models.CharField(max_length=32, choices=STATUS_CHOICES, default="ACTIVE")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "Security Payload"
        verbose_name_plural = "Security Payloads"

    def __str__(self):
        return f"Payload #{self.id} [{self.status}] - {self.label or self.endpoint}"

    @property
    def is_active(self):
        return self.status == "ACTIVE"


class SecurityEvent(models.Model):
    event_type = models.CharField(max_length=64, default="stored_xss_detected")
    source_ip = models.CharField(max_length=64, blank=True, default="127.0.0.1")
    method = models.CharField(max_length=16, blank=True, default="POST")
    path = models.CharField(max_length=255, blank=True, default="/dispatch/")
    query_string = models.TextField(blank=True, default="")
    user_agent = models.TextField(blank=True, default="")
    request_headers = models.JSONField(default=dict, blank=True)
    request_body = models.TextField(blank=True, default="")
    matched_signatures = models.JSONField(default=list, blank=True)
    payload_reference = models.CharField(max_length=255, blank=True, default="")
    payload_id = models.IntegerField(null=True, blank=True)
    raw_event = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    @property
    def http_method(self):
        return self.method

    @property
    def request_path(self):
        return self.path


    class Meta:
        ordering = ["-created_at"]
        verbose_name = "Security Event Telemetry"
        verbose_name_plural = "Security Event Telemetry"

    def __str__(self):
        return f"Event #{self.id} [{self.event_type}] from {self.source_ip}"


class IOC(models.Model):
    IOC_TYPE_CHOICES = [
        ("IP", "IPv4 / IPv6 Address"),
        ("DOMAIN", "Domain Name"),
        ("URL", "Target URL"),
        ("HASH", "Cryptographic Hash"),
        ("USER_AGENT", "Suspicious User-Agent"),
        ("PAYLOAD_PATTERN", "Payload Signature"),
    ]

    REPUTATION_CHOICES = [
        ("MALICIOUS", "Malicious"),
        ("SUSPICIOUS", "Suspicious"),
        ("UNKNOWN", "Unknown"),
        ("CLEAN", "Clean"),
    ]

    value = models.TextField(help_text="Observed raw indicator value")
    ioc_type = models.CharField(max_length=32, choices=IOC_TYPE_CHOICES)
    source_event = models.ForeignKey(
        SecurityEvent,
        on_delete=models.CASCADE,
        related_name="iocs",
        null=True,
        blank=True
    )
    normalized_value = models.TextField(help_text="Standardized/normalized indicator value")
    reputation = models.CharField(max_length=64, choices=REPUTATION_CHOICES, default="UNKNOWN")
    confidence = models.IntegerField(default=0, help_text="Confidence percentage 0-100")
    enrichment = models.JSONField(default=dict, blank=True, help_text="Enrichment intelligence details")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "Indicator of Compromise (IOC)"
        verbose_name_plural = "Indicators of Compromise (IOCs)"

    def __str__(self):
        return f"IOC [{self.ioc_type}] {self.normalized_value} ({self.reputation})"


class SecurityIncident(models.Model):
    SEVERITY_CHOICES = [
        ("LOW", "Low"),
        ("MEDIUM", "Medium"),
        ("HIGH", "High"),
        ("CRITICAL", "Critical"),
    ]

    STATUS_CHOICES = [
        ("OPEN", "Open"),
        ("INVESTIGATING", "Investigating"),
        ("CONTAINED", "Contained"),
        ("CLOSED", "Closed"),
    ]

    title = models.CharField(max_length=255)
    attack_type = models.CharField(max_length=64, default="Stored XSS")
    severity = models.CharField(max_length=16, choices=SEVERITY_CHOICES, default="HIGH")
    confidence = models.IntegerField(default=85)
    status = models.CharField(max_length=32, choices=STATUS_CHOICES, default="OPEN")
    source_ip = models.CharField(max_length=64, blank=True, default="127.0.0.1")
    endpoint = models.CharField(max_length=255, blank=True, default="/dispatch/")
    payload = models.TextField(blank=True, default="")
    matched_sigma_rule = models.CharField(max_length=255, blank=True, default="")
    risk_score = models.IntegerField(default=0)

    risk_breakdown = models.JSONField(default=list, blank=True)
    sigma_details = models.JSONField(default=dict, blank=True)

    event = models.ForeignKey(
        SecurityEvent,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="incidents"
    )
    payload_record = models.ForeignKey(
        SecurityLabPayload,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="incidents"
    )
    surveillance_request = models.ForeignKey(
        "tracker.SurveillanceRequest",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="security_incidents",
        help_text="Associated surveillance request record containing the injection payload"
    )
    action_taken_by = models.ForeignKey(
        "tracker.SpyUser",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="security_actions"
    )

    created_at = models.DateTimeField(auto_now_add=True)
    reviewed_at = models.DateTimeField(null=True, blank=True)
    action_taken_at = models.DateTimeField(null=True, blank=True)
    action_result = models.TextField(blank=True, default="")
    containment_verified = models.BooleanField(default=False)

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "Security Incident"
        verbose_name_plural = "Security Incidents"

    def __str__(self):
        return f"Incident #{self.id} [{self.severity} / {self.status}] {self.title}"

    @property
    def is_contained(self):
        return self.status == "CONTAINED"
