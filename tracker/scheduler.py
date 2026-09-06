import logging
from threading import Event
from datetime import datetime

from apscheduler.schedulers.background import BackgroundScheduler

from tracker.services.scan_campaigns import scan_campaigns


logger = logging.getLogger(__name__)
_scheduler = None
_started = False


def start():
    global _scheduler, _started

    if _started:
        return _scheduler

    scheduler = BackgroundScheduler()
    scheduler.add_job(
        scan_campaigns,
        "interval",
        minutes=5,
        id="scan_campaigns",
        replace_existing=True,
        max_instances=1,
        coalesce=True,
        next_run_time=datetime.now(),
    )
    scheduler.start()

    _scheduler = scheduler
    _started = True

    logger.info("APScheduler started")

    return scheduler


def wait_forever():
    Event().wait()
