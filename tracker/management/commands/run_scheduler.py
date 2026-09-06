from django.core.management.base import BaseCommand

from tracker.scheduler import start, wait_forever


class Command(BaseCommand):

    help = "Run the APScheduler scan loop"

    def handle(self, *args, **options):
        start()

        self.stdout.write(
            self.style.SUCCESS("Scheduler started")
        )

        wait_forever()
