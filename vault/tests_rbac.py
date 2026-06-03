"""Org-membership RBAC across the vault web UI and REST API.

Replaces the old owner==request.user boundary: access is now decided by the
caller's Membership role in the project's organization (viewer < member <
admin < owner). These tests cover per-role capability matrices, cross-org
isolation (a member of org A must never reach org B's resources), and that the
single-user personal-org flow still works.
"""

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient, APITestCase

from organizations.models import Membership, Organization, membership_for
from organizations.permissions import ProjectInOrganization

from . import crypto
from .models import Project, ProjectAPIKey, Secret
from .tests_authz import PASSPHRASE, make_project, make_secret, verified_login
from .views import CURRENT_ORG_SESSION

User = get_user_model()


def member_of(org, role, username):
    user = User.objects.create_user(username=username, password="pw")
    Membership.objects.create(organization=org, user=user, role=role)
    return user


def org_project(owner, org, name="prod"):
    """Create a project owned by `owner` but explicitly placed in `org`."""
    salt = crypto.generate_salt()
    key = crypto.derive_key(PASSPHRASE, salt)
    project = Project.objects.create(
        owner=owner,
        organization=org,
        public_id=Project.new_public_id(),
        name=name,
    )
    env = project.default_environment
    env.salt = salt
    env.verifier = crypto.make_verifier(key)
    env.save(update_fields=["salt", "verifier"])
    return project, key


# ---------------------------------------------------------------------------
# membership_for helper
# ---------------------------------------------------------------------------

class MembershipForTests(TestCase):
    def setUp(self):
        self.org = Organization.objects.create(name="Acme", slug="acme")
        self.user = member_of(self.org, Membership.ROLE_ADMIN, "alice")

    def test_returns_membership_for_member(self):
        m = membership_for(self.user, self.org)
        self.assertIsNotNone(m)
        self.assertEqual(m.role, Membership.ROLE_ADMIN)

    def test_returns_none_for_non_member(self):
        outsider = User.objects.create_user(username="bob", password="pw")
        self.assertIsNone(membership_for(outsider, self.org))

    def test_returns_none_for_anonymous(self):
        from django.contrib.auth.models import AnonymousUser

        self.assertIsNone(membership_for(AnonymousUser(), self.org))

    def test_returns_none_for_no_org(self):
        self.assertIsNone(membership_for(self.user, None))


# ---------------------------------------------------------------------------
# Web UI: per-role capability matrix within one org
# ---------------------------------------------------------------------------

class WebRoleCapabilityTests(TestCase):
    """One shared organization, one project; four users with different roles.
    Each role gets exactly the access its rank implies."""

    def setUp(self):
        self.org = Organization.objects.create(name="Shared", slug="shared")
        self.owner = member_of(self.org, Membership.ROLE_OWNER, "owner")
        self.admin = member_of(self.org, Membership.ROLE_ADMIN, "admin")
        self.member = member_of(self.org, Membership.ROLE_MEMBER, "member")
        self.viewer = member_of(self.org, Membership.ROLE_VIEWER, "viewer")
        self.project, self.key = org_project(self.owner, self.org)
        self.secret = make_secret(self.project, self.key, name="db", value="hunter2")

    def _client_for(self, user):
        c = self.client_class()
        verified_login(c, user)
        # Act under the shared org, not the user's auto-created personal org, so
        # project creation is gated against this org's role.
        session = c.session
        session[CURRENT_ORG_SESSION] = self.org.id
        session.save()
        return c

    def _detail_url(self):
        return reverse("vault:detail", kwargs={"public_id": self.project.public_id})

    def _add_url(self):
        return reverse("vault:secret_add", kwargs={"public_id": self.project.public_id})

    def _unlock(self, c):
        return c.post(
            reverse("vault:unlock", kwargs={"public_id": self.project.public_id}),
            {"passphrase": PASSPHRASE},
        )

    # --- read: every role can view the project --------------------------

    def test_all_roles_can_view_detail(self):
        for user in (self.owner, self.admin, self.member, self.viewer):
            c = self._client_for(user)
            res = c.get(self._detail_url())
            self.assertEqual(res.status_code, 200, msg=user.username)

    def test_viewer_can_unlock_and_reveal(self):
        c = self._client_for(self.viewer)
        self._unlock(c)
        revealed = c.get(self._detail_url() + f"?reveal={self.secret.id}")
        self.assertContains(revealed, "hunter2")

    # --- write secrets: member and up ------------------------------------

    def test_viewer_cannot_add_secret(self):
        c = self._client_for(self.viewer)
        self._unlock(c)
        res = c.post(self._add_url(), {"key": "NEW", "value": "v"})
        self.assertEqual(res.status_code, 404)
        self.assertFalse(Secret.objects.filter(project=self.project, key="NEW").exists())

    def test_member_can_add_secret(self):
        c = self._client_for(self.member)
        self._unlock(c)
        res = c.post(self._add_url(), {"key": "NEW", "value": "v"})
        self.assertEqual(res.status_code, 302)
        self.assertTrue(Secret.objects.filter(project=self.project, key="NEW").exists())

    def test_viewer_cannot_delete_secret(self):
        c = self._client_for(self.viewer)
        url = reverse(
            "vault:secret_delete",
            kwargs={"public_id": self.project.public_id, "secret_id": self.secret.id},
        )
        res = c.post(url)
        self.assertEqual(res.status_code, 404)
        self.assertTrue(
            Secret.objects.filter(pk=self.secret.pk, deleted_at__isnull=True).exists()
        )

    def test_member_can_delete_secret(self):
        c = self._client_for(self.member)
        url = reverse(
            "vault:secret_delete",
            kwargs={"public_id": self.project.public_id, "secret_id": self.secret.id},
        )
        res = c.post(url)
        self.assertEqual(res.status_code, 302)
        self.assertFalse(
            Secret.objects.filter(pk=self.secret.pk, deleted_at__isnull=True).exists()
        )

    # --- manage keys: admin and up ---------------------------------------

    def test_member_cannot_mint_api_key(self):
        c = self._client_for(self.member)
        res = c.post(
            reverse("vault:api_key_create", kwargs={"public_id": self.project.public_id})
        )
        self.assertEqual(res.status_code, 404)
        self.assertEqual(self.project.api_keys.count(), 0)

    def test_admin_can_mint_api_key(self):
        c = self._client_for(self.admin)
        res = c.post(
            reverse("vault:api_key_create", kwargs={"public_id": self.project.public_id})
        )
        self.assertEqual(res.status_code, 302)
        self.assertEqual(self.project.api_keys.count(), 1)

    def test_member_cannot_revoke_api_key(self):
        key_obj, _ = ProjectAPIKey.generate(self.project)
        c = self._client_for(self.member)
        url = reverse(
            "vault:api_key_revoke",
            kwargs={"public_id": self.project.public_id, "key_id": key_obj.id},
        )
        res = c.post(url)
        self.assertEqual(res.status_code, 404)
        key_obj.refresh_from_db()
        self.assertTrue(key_obj.is_active())

    def test_admin_can_revoke_api_key(self):
        key_obj, _ = ProjectAPIKey.generate(self.project)
        c = self._client_for(self.admin)
        url = reverse(
            "vault:api_key_revoke",
            kwargs={"public_id": self.project.public_id, "key_id": key_obj.id},
        )
        res = c.post(url)
        self.assertEqual(res.status_code, 302)
        key_obj.refresh_from_db()
        self.assertFalse(key_obj.is_active())

    # --- manage projects: admin and up -----------------------------------

    def test_member_cannot_create_project(self):
        c = self._client_for(self.member)
        res = c.post(reverse("vault:create"), {"name": "new", "passphrase": "longenough1"})
        self.assertEqual(res.status_code, 404)
        self.assertFalse(Project.objects.filter(organization=self.org, name="new").exists())

    def test_admin_can_create_project(self):
        c = self._client_for(self.admin)
        res = c.post(reverse("vault:create"), {"name": "new", "passphrase": "longenough1"})
        self.assertEqual(res.status_code, 302)
        self.assertTrue(Project.objects.filter(organization=self.org, name="new").exists())


# ---------------------------------------------------------------------------
# Web UI: cross-organization isolation
# ---------------------------------------------------------------------------

class WebCrossOrgIsolationTests(TestCase):
    """Alice is an OWNER of org A. Bob owns org B. Alice's high privilege in A
    grants her nothing in B: she is not a member there at all."""

    def setUp(self):
        self.org_a = Organization.objects.create(name="A", slug="org-a")
        self.org_b = Organization.objects.create(name="B", slug="org-b")
        self.alice = member_of(self.org_a, Membership.ROLE_OWNER, "alice")
        self.bob = member_of(self.org_b, Membership.ROLE_OWNER, "bob")
        self.b_project, self.b_key = org_project(self.bob, self.org_b, name="b-prod")
        self.b_secret = make_secret(self.b_project, self.b_key, name="b-secret", value="bbb")
        self.b_apikey, _ = ProjectAPIKey.generate(self.b_project)
        self.client_a = self.client_class()
        verified_login(self.client_a, self.alice)

    def test_owner_of_other_org_cannot_view_project(self):
        res = self.client_a.get(
            reverse("vault:detail", kwargs={"public_id": self.b_project.public_id})
        )
        self.assertEqual(res.status_code, 404)

    def test_owner_of_other_org_not_listed_foreign_projects(self):
        res = self.client_a.get(reverse("vault:projects"))
        self.assertEqual(res.status_code, 200)
        self.assertNotIn(self.b_project, list(res.context["projects"]))
        self.assertNotContains(res, "b-prod")

    def test_owner_of_other_org_all_mutations_404(self):
        pid = self.b_project.public_id
        posts = [
            (reverse("vault:unlock", kwargs={"public_id": pid}), {"passphrase": PASSPHRASE}),
            (reverse("vault:secret_add", kwargs={"public_id": pid}), {"key": "X", "value": "Y"}),
            (reverse("vault:api_key_create", kwargs={"public_id": pid}), {}),
            (
                reverse("vault:secret_delete", kwargs={"public_id": pid, "secret_id": self.b_secret.id}),
                {},
            ),
            (
                reverse("vault:api_key_revoke", kwargs={"public_id": pid, "key_id": self.b_apikey.id}),
                {},
            ),
        ]
        for url, data in posts:
            res = self.client_a.post(url, data)
            self.assertEqual(res.status_code, 404, msg=url)
        self.assertTrue(Secret.objects.filter(pk=self.b_secret.pk).exists())
        self.b_apikey.refresh_from_db()
        self.assertTrue(self.b_apikey.is_active())


class SharedOrgMemberSeesColleagueProjectTests(TestCase):
    """Two users in the SAME org both see each other's projects — ownership is
    no longer the boundary; org membership is."""

    def setUp(self):
        self.org = Organization.objects.create(name="Team", slug="team")
        self.alice = member_of(self.org, Membership.ROLE_ADMIN, "alice")
        self.bob = member_of(self.org, Membership.ROLE_MEMBER, "bob")
        # Bob owns the project, Alice should still be able to see it.
        self.project, self.key = org_project(self.bob, self.org, name="team-prod")

    def test_colleague_can_view_project_owned_by_another(self):
        c = self.client_class()
        verified_login(c, self.alice)
        res = c.get(reverse("vault:detail", kwargs={"public_id": self.project.public_id}))
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.context["project"].pk, self.project.pk)


# ---------------------------------------------------------------------------
# Single-user personal-org flow still works
# ---------------------------------------------------------------------------

class PersonalOrgFlowTests(TestCase):
    def test_lone_user_create_view_and_mutate(self):
        user = User.objects.create_user(username="solo", password="pw")
        c = self.client_class()
        verified_login(c, user)
        # create (personal org gives owner role -> admin+ satisfied)
        res = c.post(reverse("vault:create"), {"name": "myproj", "passphrase": "longenough1"})
        self.assertEqual(res.status_code, 302)
        project = Project.objects.get(owner=user, name="myproj")
        # add a secret (owner >= member)
        add = c.post(
            reverse("vault:secret_add", kwargs={"public_id": project.public_id}),
            {"key": "K", "value": "V"},
        )
        self.assertEqual(add.status_code, 302)
        self.assertTrue(Secret.objects.filter(project=project, key="K").exists())
        # mint a key (owner >= admin)
        mint = c.post(
            reverse("vault:api_key_create", kwargs={"public_id": project.public_id})
        )
        self.assertEqual(mint.status_code, 302)
        self.assertEqual(project.api_keys.count(), 1)


# ---------------------------------------------------------------------------
# REST API: ProjectInOrganization permission + cross-org isolation
# ---------------------------------------------------------------------------

class ApiProjectInOrganizationTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="alice", password="pw")
        self.project, self.key = make_project(self.user)  # personal org assigned
        make_secret(self.project, self.key, name="gmail.com", value="v")
        self.api_key, self.token = ProjectAPIKey.generate(self.project)

    def _bearer(self):
        c = APIClient()
        c.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token}")
        return c

    def test_project_with_org_can_list(self):
        self.assertIsNotNone(self.project.organization_id)
        res = self._bearer().get("/api/secrets")
        self.assertEqual(res.status_code, 200)

    def test_permission_denied_when_project_detached_from_org(self):
        # Simulate an orphaned project: the permission must refuse it (403).
        perm = ProjectInOrganization()

        class FakeRequest:
            pass

        req = FakeRequest()
        req.user = self.project
        self.assertTrue(perm.has_permission(req, None))
        self.project.organization = None
        self.assertFalse(perm.has_permission(req, None))


class ApiCrossOrgIsolationTests(APITestCase):
    """A project key for org A can never read org B's secrets — the key is
    scoped to its single project, which belongs to exactly one org."""

    def setUp(self):
        self.org_a = Organization.objects.create(name="A", slug="api-a")
        self.org_b = Organization.objects.create(name="B", slug="api-b")
        self.alice = member_of(self.org_a, Membership.ROLE_OWNER, "alice")
        self.bob = member_of(self.org_b, Membership.ROLE_OWNER, "bob")
        self.proj_a, self.key_a = org_project(self.alice, self.org_a, name="a")
        self.proj_b, self.key_b = org_project(self.bob, self.org_b, name="b")
        make_secret(self.proj_a, self.key_a, name="a-secret", value="aaa")
        make_secret(self.proj_b, self.key_b, name="b-secret", value="bbb")
        _, self.token_a = ProjectAPIKey.generate(self.proj_a)

    def test_org_a_key_cannot_reach_org_b_secret(self):
        c = APIClient()
        c.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_a}")
        listing = c.get("/api/secrets")
        self.assertEqual(listing.status_code, 200)
        self.assertEqual(listing.json()["keys"], ["a-secret"])
        self.assertEqual(c.get("/api/secrets/b-secret").status_code, 404)
        self.assertEqual(c.get("/api/secrets/a-secret").status_code, 200)
