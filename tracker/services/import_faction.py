from tracker.models import Campaign
from tracker.models import Member

from tracker.services.torn_api import (
    get_faction_data
)


def import_faction(faction_id, api_key=None):

    data = get_faction_data(faction_id, api_key)

    if isinstance(data, dict) and data.get("error"):
        error_value = data["error"]

        if isinstance(error_value, dict):
            error_message = error_value.get("error", "Unknown Torn API error")
        else:
            error_message = str(error_value)

        raise ValueError(error_message)

    faction_name = (
        data.get("name")
        or data.get("faction_name")
        or data.get("faction", {}).get("name")
    )

    if not faction_name:
        raise ValueError("Torn API response did not include a faction name")

    members = data.get("members") or data.get("faction", {}).get("members") or {}

    campaign = Campaign.objects.create(
        faction_id=faction_id,
        faction_name=faction_name
    )

    for player_id, player_data in members.items():

        Member.objects.create(
            campaign=campaign,
            player_id=int(player_id),
            name=player_data["name"],
            level=player_data["level"],
            position=player_data["position"]
        )

    return campaign