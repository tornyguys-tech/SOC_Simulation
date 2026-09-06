from django.urls import path

from . import views


urlpatterns = [
    path(
        "",
        views.home,
        name="home"
    ),

    path(
        "health/",
        views.health,
        name="health"
    ),

    path(
        "login/",
        views.login,
        name="login"
    ),

    path(
        "logout/",
        views.logout,
        name="logout"
    ),

    path(
        "dashboard/",
        views.home,
        name="home_dashboard"
    ),

    path(
        "requests/",
        views.requests_list,
        name="requests_list"
    ),

    path(
        "requests/create/",
        views.create_request,
        name="create_request"
    ),

    path(
        "campaign/create/",
        views.create_campaign,
        name="create_campaign"
    ),

    path(
        "campaign/<int:campaign_id>/",
        views.campaign_detail,
        name="campaign_detail"
    ),

    path(
        "campaign/<int:campaign_id>/start/",
        views.start_campaign,
        name="start_campaign"
    ),

    path(
        "campaign/<int:campaign_id>/stop/",
        views.stop_campaign,
        name="stop_campaign"
    ),

    path(
        "campaign/<int:campaign_id>/export/",
        views.export_campaign_json,
        name="export_campaign"
    ),

    path(
        "campaign/<int:campaign_id>/delete/",
        views.delete_campaign,
        name="delete_campaign"
    ),

    path(
        "member/<int:member_id>/",
        views.member_detail,
        name="member_detail"
    ),

    path(
        "admin/requests/",
        views.admin_requests,
        name="admin_requests"
    ),

    path(
        "admin/requests/<int:request_id>/approve/",
        views.approve_request,
        name="approve_request"
    ),

    path(
        "admin/requests/<int:request_id>/reject/",
        views.reject_request,
        name="reject_request"
    ),
]