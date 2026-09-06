"""
URL configuration for tornspy project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/6.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import include, path
from django.conf import settings
from django.views.static import serve
from security_monitoring import views as security_views

urlpatterns = [
    path(
        "",
        include("tracker.urls")
    ),

    # Security monitoring routes use normal application-looking paths.
    path("dispatch/", security_views.xss_demo, name="xss_demo"),
    path("soc/", security_views.soc_dashboard, name="soc_dashboard"),
    path("soc/poll/", security_views.soc_poll, name="soc_poll"),
    path("soc/incident/<int:incident_id>/contain/", security_views.take_action, name="take_action"),

    path("admin/", admin.site.urls),
    path("logo.png", serve, {"document_root": settings.BASE_DIR, "path": "logo.png"}),
]