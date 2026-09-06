from django.core.management.base import BaseCommand
from tracker.models import Campaign, Snapshot

class Command(BaseCommand):

    help = "Report snapshot counts per campaign"

    def handle(self, *args, **options):

        total = Snapshot.objects.count()
        self.stdout.write(f"Total snapshots: {total}")

        for c in Campaign.objects.all():
            count = Snapshot.objects.filter(member__campaign=c).count()
            self.stdout.write(f"Campaign {c.id} ({c.faction_name}): {count} snapshots, members={c.members.count()}")
