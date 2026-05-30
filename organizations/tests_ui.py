"""Web UI for switching the current organization and managing its members.

Switching is gated by membership; member management (invite/role/remove) is
gated by the admin role, with extra guards so the last owner can never be
demoted or removed and so only an owner may touch another owner.
"""

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from vault.tests_authz import verified_login
from vault.views import CURRENT_ORG_SESSION

from .models import Membership, Organization

User = get_user_model()


def member_of(org, role, username):
    user = User.objects.create_user(username=username, password="pw")
    Membership.objects.create(organization=org, user=user, role=role)
    return user


def login_in_org(client, user, org):
    """Log the user in (clearing OTP) and pin the session's current org to
    `org`. force_login is re-applied after the session edit so the auth state
    survives the manual save."""
    verified_login(client, user)
    session = client.session
    session[CURRENT_ORG_SESSION] = org.id
    session.save()
    client.force_login(user)


class OrganizationSwitchTests(TestCase):
    def setUp(self):
        self.org_a = Organization.objects.create(name="Acme", slug="acme")
        self.org_b = Organization.objects.create(name="Beta", slug="beta")
        self.user = member_of(self.org_a, Membership.ROLE_OWNER, "alice")
        Membership.objects.create(
            organization=self.org_b, user=self.user, role=Membership.ROLE_MEMBER
        )
        verified_login(self.client, self.user)

    def test_list_shows_all_memberships(self):
        resp = self.client.get(reverse("organizations:list"))
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "Acme")
        self.assertContains(resp, "Beta")

    def test_switch_sets_session(self):
        resp = self.client.post(
            reverse("organizations:switch", args=[self.org_b.id])
        )
        self.assertRedirects(resp, reverse("organizations:list"))
        self.assertEqual(self.client.session[CURRENT_ORG_SESSION], self.org_b.id)

    def test_cannot_switch_to_foreign_org(self):
        outsider_org = Organization.objects.create(name="Gamma", slug="gamma")
        resp = self.client.post(
            reverse("organizations:switch", args=[outsider_org.id])
        )
        self.assertEqual(resp.status_code, 404)

    def test_switch_requires_post(self):
        resp = self.client.get(reverse("organizations:switch", args=[self.org_b.id]))
        self.assertRedirects(resp, reverse("organizations:list"))
        self.assertNotEqual(
            self.client.session.get(CURRENT_ORG_SESSION), self.org_b.id
        )


class MemberListTests(TestCase):
    def setUp(self):
        self.org = Organization.objects.create(name="Acme", slug="acme")

    def test_admin_sees_management_controls(self):
        admin = member_of(self.org, Membership.ROLE_ADMIN, "admin")
        login_in_org(self.client, admin, self.org)
        resp = self.client.get(reverse("organizations:members"))
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "Invite an existing user")

    def test_viewer_sees_readonly_list(self):
        viewer = member_of(self.org, Membership.ROLE_VIEWER, "viewer")
        login_in_org(self.client, viewer, self.org)
        resp = self.client.get(reverse("organizations:members"))
        self.assertEqual(resp.status_code, 200)
        self.assertNotContains(resp, "Invite an existing user")

    def test_list_scoped_to_current_org_only(self):
        # A member of two orgs only sees the members of the one the session is
        # currently acting under, never the other org's members.
        other = Organization.objects.create(name="Beta", slug="beta")
        member_of(other, Membership.ROLE_OWNER, "beta_owner")
        viewer = member_of(self.org, Membership.ROLE_VIEWER, "viewer")
        Membership.objects.create(
            organization=other, user=viewer, role=Membership.ROLE_VIEWER
        )
        login_in_org(self.client, viewer, self.org)
        resp = self.client.get(reverse("organizations:members"))
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "viewer")
        self.assertNotContains(resp, "beta_owner")


class MemberInviteTests(TestCase):
    def setUp(self):
        self.org = Organization.objects.create(name="Acme", slug="acme")
        self.admin = member_of(self.org, Membership.ROLE_ADMIN, "admin")
        self.target = User.objects.create_user(username="carol", password="pw")
        login_in_org(self.client, self.admin, self.org)

    def test_admin_can_invite_existing_user(self):
        resp = self.client.post(
            reverse("organizations:member_invite"),
            {"username": "carol", "role": Membership.ROLE_MEMBER},
        )
        self.assertRedirects(resp, reverse("organizations:members"))
        self.assertTrue(
            Membership.objects.filter(organization=self.org, user=self.target).exists()
        )

    def test_invite_unknown_username_is_rejected(self):
        self.client.post(
            reverse("organizations:member_invite"),
            {"username": "nobody", "role": Membership.ROLE_MEMBER},
        )
        self.assertEqual(self.org.memberships.count(), 1)

    def test_invite_duplicate_member_is_rejected(self):
        Membership.objects.create(
            organization=self.org, user=self.target, role=Membership.ROLE_VIEWER
        )
        self.client.post(
            reverse("organizations:member_invite"),
            {"username": "carol", "role": Membership.ROLE_MEMBER},
        )
        m = Membership.objects.get(organization=self.org, user=self.target)
        self.assertEqual(m.role, Membership.ROLE_VIEWER)

    def test_member_cannot_invite(self):
        member = member_of(self.org, Membership.ROLE_MEMBER, "dave")
        login_in_org(self.client, member, self.org)
        resp = self.client.post(
            reverse("organizations:member_invite"),
            {"username": "carol", "role": Membership.ROLE_MEMBER},
        )
        self.assertEqual(resp.status_code, 404)


class MemberRoleTests(TestCase):
    def setUp(self):
        self.org = Organization.objects.create(name="Acme", slug="acme")
        self.owner = member_of(self.org, Membership.ROLE_OWNER, "owner")
        self.member_user = member_of(self.org, Membership.ROLE_MEMBER, "carol")
        self.member = Membership.objects.get(
            organization=self.org, user=self.member_user
        )

    def test_admin_can_change_role(self):
        admin = member_of(self.org, Membership.ROLE_ADMIN, "admin")
        login_in_org(self.client, admin, self.org)
        self.client.post(
            reverse("organizations:member_role", args=[self.member.id]),
            {"role": Membership.ROLE_ADMIN},
        )
        self.member.refresh_from_db()
        self.assertEqual(self.member.role, Membership.ROLE_ADMIN)

    def test_admin_cannot_change_owner_role(self):
        admin = member_of(self.org, Membership.ROLE_ADMIN, "admin")
        login_in_org(self.client, admin, self.org)
        owner_m = Membership.objects.get(organization=self.org, user=self.owner)
        self.client.post(
            reverse("organizations:member_role", args=[owner_m.id]),
            {"role": Membership.ROLE_MEMBER},
        )
        owner_m.refresh_from_db()
        self.assertEqual(owner_m.role, Membership.ROLE_OWNER)

    def test_cannot_demote_last_owner(self):
        login_in_org(self.client, self.owner, self.org)
        owner_m = Membership.objects.get(organization=self.org, user=self.owner)
        self.client.post(
            reverse("organizations:member_role", args=[owner_m.id]),
            {"role": Membership.ROLE_ADMIN},
        )
        owner_m.refresh_from_db()
        self.assertEqual(owner_m.role, Membership.ROLE_OWNER)


class MemberRemoveTests(TestCase):
    def setUp(self):
        self.org = Organization.objects.create(name="Acme", slug="acme")
        self.owner = member_of(self.org, Membership.ROLE_OWNER, "owner")
        self.victim_user = member_of(self.org, Membership.ROLE_MEMBER, "carol")
        self.victim = Membership.objects.get(
            organization=self.org, user=self.victim_user
        )

    def test_admin_can_remove_member(self):
        admin = member_of(self.org, Membership.ROLE_ADMIN, "admin")
        login_in_org(self.client, admin, self.org)
        self.client.post(
            reverse("organizations:member_remove", args=[self.victim.id])
        )
        self.assertFalse(Membership.objects.filter(id=self.victim.id).exists())

    def test_cannot_remove_last_owner(self):
        login_in_org(self.client, self.owner, self.org)
        owner_m = Membership.objects.get(organization=self.org, user=self.owner)
        self.client.post(
            reverse("organizations:member_remove", args=[owner_m.id])
        )
        self.assertTrue(Membership.objects.filter(id=owner_m.id).exists())

    def test_admin_cannot_remove_owner(self):
        admin = member_of(self.org, Membership.ROLE_ADMIN, "admin")
        login_in_org(self.client, admin, self.org)
        owner_m = Membership.objects.get(organization=self.org, user=self.owner)
        self.client.post(
            reverse("organizations:member_remove", args=[owner_m.id])
        )
        self.assertTrue(Membership.objects.filter(id=owner_m.id).exists())
