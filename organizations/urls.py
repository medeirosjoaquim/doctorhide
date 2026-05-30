from django.urls import path

from . import views

app_name = "organizations"

urlpatterns = [
    path("orgs", views.organization_list, name="list"),
    path("orgs/<int:org_id>/switch", views.organization_switch, name="switch"),
    path("orgs/members", views.member_list, name="members"),
    path("orgs/members/invite", views.member_invite, name="member_invite"),
    path("orgs/members/<int:membership_id>/role", views.member_role, name="member_role"),
    path("orgs/members/<int:membership_id>/remove", views.member_remove, name="member_remove"),
]
