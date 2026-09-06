from django.core.management.base import BaseCommand

from tracker.services.scan_campaigns import (
    scan_campaigns
)

class Command(BaseCommand):

    help = "Scan active campaigns"

    def handle(self, *args, **kwargs):

        count = scan_campaigns()

        self.stdout.write(
            self.style.SUCCESS(
                f"Scanned {count} campaigns"
            )
        )