"""DRF permission helpers for organization-membership RBAC.

A view gates access by declaring a minimum role; the caller must hold a
membership in the object's organization that is at least that privileged.
Roles, from least to most privileged: viewer < member < admin < owner.
"""

from rest_framework.permissions import BasePermission

from .models import Membership, membership_for


def organization_of(obj):
    """Best-effort resolve the Organization an object belongs to."""
    org = getattr(obj, "organization", None)
    if org is not None:
        return org
    project = getattr(obj, "project", None)
    if project is not None:
        return getattr(project, "organization", None)
    return None


class HasOrgRole(BasePermission):
    """Object-level permission requiring an org membership of at least
    ``required_role`` (default: viewer). Set the minimum on the view via the
    ``required_role`` attribute. Enforces that a caller cannot touch resources
    belonging to an organization they are not a member of.
    """

    required_role = Membership.ROLE_VIEWER

    def _min_role(self, view):
        return getattr(view, "required_role", self.required_role)

    def has_object_permission(self, request, view, obj):
        organization = organization_of(obj)
        if organization is None:
            return False
        membership = membership_for(request.user, organization)
        if membership is None:
            return False
        return membership.at_least(self._min_role(view))


class ProjectInOrganization(BasePermission):
    """API guard for the project-key (dhk_) endpoints, where the principal is a
    Project, not a user. A dhk_ key resolves to exactly one project, so this
    asserts that project still belongs to an organization — the structural
    boundary that keeps one tenant's key from ever reaching another tenant's
    data. Returns False (403) if the project has been detached from its org.
    """

    def has_permission(self, request, view):
        project = request.user
        return getattr(project, "organization_id", None) is not None
