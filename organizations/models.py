from django.conf import settings
from django.db import models


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
