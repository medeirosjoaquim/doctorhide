from django.conf import settings
from django.db import models
from django.utils.text import slugify


class Organization(models.Model):
    name = models.CharField(max_length=255)
    slug = models.SlugField(max_length=255, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name


class Membership(models.Model):
    """Links a user to an organization with a role. The role hierarchy is
    owner > admin > member > viewer, so a higher role implies every privilege
    of the roles below it (see at_least)."""

    ROLE_OWNER = "owner"
    ROLE_ADMIN = "admin"
    ROLE_MEMBER = "member"
    ROLE_VIEWER = "viewer"
    ROLE_CHOICES = [
        (ROLE_OWNER, "Owner"),
        (ROLE_ADMIN, "Admin"),
        (ROLE_MEMBER, "Member"),
        (ROLE_VIEWER, "Viewer"),
    ]
    # Higher number = more privileged. Used by at_least for comparisons.
    ROLE_RANK = {
        ROLE_VIEWER: 0,
        ROLE_MEMBER: 1,
        ROLE_ADMIN: 2,
        ROLE_OWNER: 3,
    }

    organization = models.ForeignKey(
        Organization, on_delete=models.CASCADE, related_name="memberships"
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="memberships"
    )
    role = models.CharField(max_length=16, choices=ROLE_CHOICES, default=ROLE_MEMBER)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ("organization", "user")

    def __str__(self):
        return f"{self.user} @ {self.organization} ({self.role})"

    def has_role(self, role: str) -> bool:
        """True only if this membership's role is exactly `role`."""
        return self.role == role

    def at_least(self, role: str) -> bool:
        """True if this membership's role is at least as privileged as `role`."""
        return self.ROLE_RANK[self.role] >= self.ROLE_RANK[role]


def _unique_slug(base):
    base = slugify(base) or "org"
    slug = base
    n = 1
    while Organization.objects.filter(slug=slug).exists():
        n += 1
        slug = f"{base}-{n}"
    return slug


def personal_organization(user):
    """Return the organization the user owns, creating a personal one (with an
    owner membership) the first time it is needed."""
    membership = (
        Membership.objects.filter(user=user, role=Membership.ROLE_OWNER)
        .select_related("organization")
        .order_by("organization__id")
        .first()
    )
    if membership is not None:
        return membership.organization

    org = Organization.objects.create(
        name=f"{user.get_username()}'s organization",
        slug=_unique_slug(user.get_username()),
    )
    Membership.objects.create(
        organization=org, user=user, role=Membership.ROLE_OWNER
    )
    return org
