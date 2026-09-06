from pathlib import Path
import os

from django.conf import settings
from django.core.management.base import BaseCommand

from tracker.models import Campaign, Snapshot


def _pid_file(name):
    return Path(settings.BASE_DIR) / "logs" / f"{name}.pid"


def _process_running(pid_file):
    if not pid_file.exists():
        return False

    try:
        pid = int(pid_file.read_text(encoding="utf-8").strip())
    except (TypeError, ValueError, OSError):
        return False

    try:
        os.kill(pid, 0)
    except OSError:
        return False

    return True


class Command(BaseCommand):

    help = "Report TornSpy runtime status"

    def handle(self, *args, **options):
        scheduler_running = _process_running(_pid_file("scheduler"))
        server_running = _process_running(_pid_file("server"))

        database_ok = True
        campaign_count = 0
        snapshot_count = 0

        try:
            campaign_count = Campaign.objects.count()
            snapshot_count = Snapshot.objects.count()
        except Exception:
            database_ok = False

        self.stdout.write("TORNSPY INTELLIGENCE WAR ROOM")
        self.stdout.write(
            f"Scheduler: {'RUNNING' if scheduler_running else 'STOPPED'}"
        )
        self.stdout.write(
            f"Django: {'RUNNING' if server_running else 'STOPPED'}"
        )
        self.stdout.write(
            f"Server: {'RUNNING' if server_running else 'STOPPED'}"
        )
        self.stdout.write(
            f"Database: {'OK' if database_ok else 'ERROR'}"
        )
        self.stdout.write(f"Campaign count: {campaign_count}")
        self.stdout.write(f"Snapshot count: {snapshot_count}")