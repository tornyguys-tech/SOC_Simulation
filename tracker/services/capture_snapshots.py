import logging

from tracker.models import Snapshot

from tracker.services.torn_api import (
    get_faction_data
)


logger = logging.getLogger(__name__)


def capture_snapshots(campaign, api_key=None):
    # Defensive capture with diagnostic output for debugging
    data = get_faction_data(campaign.faction_id, api_key)

    api_members = data.get("members") or {}

    db_members = list(campaign.members.all())

    api_count = len(api_members)
    db_count = len(db_members)

    logger.info(
        "Scanning campaign %s (%s) - api_members=%s db_members=%s",
        campaign.id,
        campaign.faction_name,
        api_count,
        db_count,
    )

    created = 0
    matched = 0

    for member in db_members:

        player_data = api_members.get(str(member.player_id))

        if not player_data:
            continue

        matched += 1

        last_action = player_data.get("last_action") or {}
        status = player_data.get("status") or {}

        online_status = last_action.get("status") or ""
        last_action_timestamp = last_action.get("timestamp")
        last_action_relative = last_action.get("relative") or ""
        current_status = status.get("description") or ""
        current_state = status.get("state") or ""

        Snapshot.objects.create(
            member=member,
            online_status=online_status,
            last_action_timestamp=last_action_timestamp,
            last_action_relative=last_action_relative,
            current_status=current_status,
            current_state=current_state,
            raw_json=player_data
        )

        created += 1

    logger.info(
        "Finished campaign %s: matched=%s created=%s",
        campaign.id,
        matched,
        created,
    )