from django.contrib import messages
from django.contrib.auth import get_user_model
from django.http import Http404
from django.shortcuts import get_object_or_404, redirect, render
from django_otp.decorators import otp_required

from vault.views import CURRENT_ORG_SESSION, current_organization

from .models import Membership, Organization, membership_for

User = get_user_model()

# Roles a membership may be assigned through the management UI. Owner is granted
# only via the personal-org flow / transfer, never handed out here.
ASSIGNABLE_ROLES = [
    Membership.ROLE_ADMIN,
    Membership.ROLE_MEMBER,
    Membership.ROLE_VIEWER,
]


def _require_role(request, org, role):
    """Return the caller's membership in `org` if it is at least `role`,
    otherwise raise 404 so the tenant boundary never leaks."""
    membership = membership_for(request.user, org)
    if membership is None or not membership.at_least(role):
        raise Http404("No such organization.")
    return membership


@otp_required
def organization_list(request):
    """List every organization the caller belongs to and let them switch the
    one the session is acting under."""
    current = current_organization(request)
    memberships = (
        request.user.memberships.select_related("organization")
        .order_by("organization__name")
    )
    return render(
        request,
        "organizations/organizations.html",
        {"memberships": memberships, "current": current},
    )


@otp_required
def organization_switch(request, org_id):
    """Set the session's current organization, only if the caller is a member."""
    if request.method == "POST":
        org = Organization.objects.filter(
            id=org_id, memberships__user=request.user
        ).first()
        if org is None:
            raise Http404("No such organization.")
        request.session[CURRENT_ORG_SESSION] = org.id
    return redirect("organizations:list")


@otp_required
def member_list(request):
    """List the members of the current organization. Admins and owners may
    manage them; everyone else gets a read-only view."""
    org = current_organization(request)
    membership = membership_for(request.user, org)
    if membership is None:
        raise Http404("No such organization.")
    can_manage = membership.at_least(Membership.ROLE_ADMIN)
    members = (
        org.memberships.select_related("user").order_by("user__username")
    )
    return render(
        request,
        "organizations/members.html",
        {
            "organization": org,
            "members": members,
            "can_manage": can_manage,
            "is_owner": membership.at_least(Membership.ROLE_OWNER),
            "assignable_roles": Membership.ROLE_CHOICES,
        },
    )


@otp_required
def member_invite(request):
    """Add an existing user to the current organization by username."""
    org = current_organization(request)
    _require_role(request, org, Membership.ROLE_ADMIN)
    if request.method == "POST":
        username = request.POST.get("username", "").strip()
        role = request.POST.get("role", Membership.ROLE_MEMBER)
        if role not in ASSIGNABLE_ROLES:
            messages.error(request, "Invalid role.")
        else:
            user = User.objects.filter(username__iexact=username).first()
            if user is None:
                messages.error(request, "No user with that username.")
            elif Membership.objects.filter(organization=org, user=user).exists():
                messages.error(request, "That user is already a member.")
            else:
                Membership.objects.create(organization=org, user=user, role=role)
                messages.success(request, f"Added {user.get_username()}.")
    return redirect("organizations:members")


@otp_required
def member_role(request, membership_id):
    """Change a member's role. Owner memberships can only be edited by an owner,
    and the last owner can never be demoted."""
    org = current_organization(request)
    actor = _require_role(request, org, Membership.ROLE_ADMIN)
    target = get_object_or_404(Membership, id=membership_id, organization=org)
    if request.method == "POST":
        role = request.POST.get("role", "")
        if role not in ASSIGNABLE_ROLES:
            messages.error(request, "Invalid role.")
        elif target.role == Membership.ROLE_OWNER and not actor.at_least(
            Membership.ROLE_OWNER
        ):
            messages.error(request, "Only an owner can change an owner's role.")
        elif (
            target.role == Membership.ROLE_OWNER
            and org.memberships.filter(role=Membership.ROLE_OWNER).count() == 1
        ):
            messages.error(request, "An organization must keep at least one owner.")
        else:
            target.role = role
            target.save(update_fields=["role"])
            messages.success(request, "Role updated.")
    return redirect("organizations:members")


@otp_required
def member_remove(request, membership_id):
    """Remove a member from the current organization. The last owner cannot be
    removed."""
    org = current_organization(request)
    actor = _require_role(request, org, Membership.ROLE_ADMIN)
    target = get_object_or_404(Membership, id=membership_id, organization=org)
    if request.method == "POST":
        if target.role == Membership.ROLE_OWNER and not actor.at_least(
            Membership.ROLE_OWNER
        ):
            messages.error(request, "Only an owner can remove an owner.")
        elif (
            target.role == Membership.ROLE_OWNER
            and org.memberships.filter(role=Membership.ROLE_OWNER).count() == 1
        ):
            messages.error(request, "An organization must keep at least one owner.")
        else:
            target.delete()
            messages.success(request, "Member removed.")
    return redirect("organizations:members")
