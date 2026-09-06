from django.db.models import Count
from django.utils import timezone

from tracker.models import Campaign


def export_campaign(campaign_id):

    campaign = Campaign.objects.get(
        id=campaign_id
    )

    data = {
        "campaign": {
            "id": campaign.id,
            "faction_id": campaign.faction_id,
            "faction_name": campaign.faction_name,
            "active": campaign.active,
            "member_count": campaign.members.count(),
            "snapshot_count": campaign.members.aggregate(
                snapshot_count=Count("snapshots")
            )["snapshot_count"] or 0,
            "started_at": campaign.started_at.isoformat(),
            "exported_at": timezone.now().isoformat(),
        },
        "members": []
    }

    for member in campaign.members.all():

        member_data = {
            "player_id": member.player_id,
            "name": member.name,
            "level": member.level,
            "position": member.position,
            "snapshots": []
        }

        snapshots = member.snapshots.order_by(
            "captured_at"
        )

        for snapshot in snapshots:

            member_data["snapshots"].append({
                "captured_at":
                    snapshot.captured_at.isoformat(),

                "online_status":
                    snapshot.online_status,

                "last_action_timestamp":
                    snapshot.last_action_timestamp,

                "last_action_relative":
                    snapshot.last_action_relative,

                "current_status":
                    snapshot.current_status,

                "current_state":
                    snapshot.current_state,
            })

        data["members"].append(
            member_data
        )

    return data