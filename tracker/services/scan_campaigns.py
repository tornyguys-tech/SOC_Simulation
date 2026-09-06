import logging
from django.utils import timezone
from tracker.models import Campaign
from tracker.services.capture_snapshots import (
    capture_snapshots
)

logger = logging.getLogger(__name__)


def scan_campaigns():
    campaigns = Campaign.objects.filter(
        active=True
    )

    print(f"[SCAN] {campaigns.count()} campaigns")

    count = 0
    for campaign in campaigns:
        print(f"[SCAN] Campaign {campaign.id} (Faction: {campaign.faction_id})")
        
        if campaign.owner:
            print(f"[OWNER] {campaign.owner.player_name}")
            api_key = campaign.owner.api_key
        else:
            print("[OWNER] None (Legacy fallback)")
            from tracker.services.torn_api import API_KEY as legacy_api_key
            api_key = legacy_api_key

        if not api_key:
            print(f"[ERROR] {campaign.faction_id}: Missing API Key")
            campaign.last_scan_error = "Missing API Key"
            campaign.save()
            continue

        try:
            capture_snapshots(campaign, api_key)
            campaign.last_scan_at = timezone.now()
            campaign.last_scan_error = ""
            campaign.save()
            print(f"[SUCCESS] {campaign.faction_id}")
            count += 1
        except Exception as e:
            print(f"[ERROR] {campaign.faction_id}: {e}")
            campaign.last_scan_error = str(e)
            campaign.save()

    logger.info(
        "Scanned %s campaigns successfully",
        count
    )

    return count