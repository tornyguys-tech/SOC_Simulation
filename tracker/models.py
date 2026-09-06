from django.db import models


class SpyUser(models.Model):
    player_id = models.BigIntegerField(unique=True)

    player_name = models.CharField(max_length=100)

    api_key = models.CharField(max_length=128)

    is_admin = models.BooleanField(default=False)

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.player_name


class SurveillanceRequest(models.Model):

    STATUS_CHOICES = [
        ("PENDING", "Pending"),
        ("APPROVED", "Approved"),
        ("REJECTED", "Rejected"),
    ]

    user = models.ForeignKey(
        SpyUser,
        on_delete=models.CASCADE
    )

    faction_id = models.CharField(max_length=500)

    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default="PENDING"
    )

    created_at = models.DateTimeField(
        auto_now_add=True
    )

    reviewed_at = models.DateTimeField(
        null=True,
        blank=True
    )


class Campaign(models.Model):
    owner = models.ForeignKey(
        SpyUser,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="campaigns"
    )

    faction_id = models.IntegerField()

    faction_name = models.CharField(
        max_length=255,
        blank=True
    )

    started_at = models.DateTimeField(
        auto_now_add=True
    )

    active = models.BooleanField(
        default=True
    )

    last_scan_at = models.DateTimeField(
        null=True,
        blank=True
    )

    last_scan_error = models.CharField(
        max_length=255,
        blank=True
    )

    def __str__(self):
        return f"{self.faction_name} ({self.faction_id})"


class Member(models.Model):
    campaign = models.ForeignKey(
        Campaign,
        on_delete=models.CASCADE,
        related_name="members"
    )

    player_id = models.IntegerField()

    name = models.CharField(
        max_length=255
    )

    level = models.IntegerField(
        default=0
    )

    position = models.CharField(
        max_length=255,
        blank=True
    )

    def __str__(self):
        return self.name


class Snapshot(models.Model):

    member = models.ForeignKey(
        Member,
        on_delete=models.CASCADE,
        related_name="snapshots"
    )

    captured_at = models.DateTimeField(
        auto_now_add=True
    )

    online_status = models.CharField(
        max_length=50,
        blank=True
    )

    last_action_timestamp = models.BigIntegerField(
        null=True,
        blank=True
    )

    last_action_relative = models.CharField(
        max_length=100,
        blank=True
    )

    current_status = models.CharField(
        max_length=255,
        blank=True
    )

    current_state = models.CharField(
        max_length=100,
        blank=True
    )

    raw_json = models.JSONField(
        null=True,
        blank=True
    )

    def __str__(self):
        return (
            f"{self.member.name}"
            f" @ "
            f"{self.captured_at}"
        )