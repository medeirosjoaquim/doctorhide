"""Tests for scoping projects to an organization: the current-organization
resolver, the project_create web view attaching the org, and the auto-assigned
personal organization on direct Project creation."""

from django.contrib.auth import get_user_model
from django.test import RequestFactory, TestCase
from django.urls import reverse

from organizations.models import Membership, Organization

from .models import Project
from .views import CURRENT_ORG_SESSION, current_organization
from .tests_authz import verified_login

User = get_user_model()


class PersonalOrganizationTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="alice", password="pw")

    def test_direct_create_assigns_personal_org(self):
        project = Project.objects.create(
            owner=self.user,
            public_id=Project.new_public_id(),
            name="prod",
            salt="s" * 16,
            verifier="v",
        )
        self.assertIsNotNone(project.organization)
        membership = Membership.objects.get(
            user=self.user, organization=project.organization
        )
        self.assertEqual(membership.role, Membership.ROLE_OWNER)

    def test_personal_org_is_reused_across_projects(self):
        first = Project.objects.create(
            owner=self.user,
            public_id=Project.new_public_id(),
            name="one",
            salt="s" * 16,
            verifier="v",
        )
        second = Project.objects.create(
            owner=self.user,
            public_id=Project.new_public_id(),
            name="two",
            salt="s" * 16,
            verifier="v",
        )
        self.assertEqual(first.organization_id, second.organization_id)
        self.assertEqual(
            Organization.objects.filter(memberships__user=self.user).count(), 1
        )


class CurrentOrganizationResolverTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.user = User.objects.create_user(username="bob", password="pw")

    def _request(self, session=None):
        request = self.factory.get("/")
        request.user = self.user
        request.session = session if session is not None else {}
        return request

    def test_default_is_first_owned_org(self):
        owned = Organization.objects.create(name="Owned", slug="owned")
        Membership.objects.create(
            organization=owned, user=self.user, role=Membership.ROLE_OWNER
        )
        request = self._request()
        self.assertEqual(current_organization(request).id, owned.id)
        self.assertEqual(request.session[CURRENT_ORG_SESSION], owned.id)

    def test_session_selection_is_honoured(self):
        a = Organization.objects.create(name="A", slug="a")
        b = Organization.objects.create(name="B", slug="b")
        Membership.objects.create(
            organization=a, user=self.user, role=Membership.ROLE_OWNER
        )
        Membership.objects.create(
            organization=b, user=self.user, role=Membership.ROLE_MEMBER
        )
        request = self._request(session={CURRENT_ORG_SESSION: b.id})
        self.assertEqual(current_organization(request).id, b.id)

    def test_session_org_for_non_member_is_ignored(self):
        other = Organization.objects.create(name="Other", slug="other")
        request = self._request(session={CURRENT_ORG_SESSION: other.id})
        resolved = current_organization(request)
        self.assertNotEqual(resolved.id, other.id)
        membership = Membership.objects.get(user=self.user, organization=resolved)
        self.assertEqual(membership.role, Membership.ROLE_OWNER)


class ProjectCreateViewTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="carol", password="pw")
        verified_login(self.client, self.user)

    def test_create_attaches_current_organization(self):
        response = self.client.post(
            reverse("vault:create"),
            {"name": "prod", "passphrase": "passphrase1"},
        )
        self.assertEqual(response.status_code, 302)
        project = Project.objects.get(owner=self.user, name="prod")
        self.assertTrue(
            Membership.objects.filter(
                user=self.user,
                organization=project.organization,
                role=Membership.ROLE_OWNER,
            ).exists()
        )
