from django.urls import path
from . import views

# Legacy compatibility is intentionally kept out of the main UI. The public
# application routes are registered in tornspy/urls.py as /dispatch/ and /soc/.
urlpatterns = [
    path("", views.xss_demo, name="security_monitoring_root"),
    path("status/", views.api_status, name="api_status"),
    path("poll/", views.soc_poll, name="api_soc_poll"),
]
