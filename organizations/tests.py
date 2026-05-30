from django.contrib.auth import get_user_model
from django.db import IntegrityError, transaction
from django.test import TestCase

from .models import Membership, Organization


class OrganizationModelTests(TestCase):
    def test_create_organization(self):
        org = Organization.objects.create(name="Acme", slug="acme")
        self.assertEqual(str(org), "Acme")
        self.assertIsNotNone(org.created_at)

    def test_slug_is_unique(self):
        Organization.objects.create(name="Acme", slug="acme")
        with self.assertRaises(IntegrityError):
            Organization.objects.create(name="Acme Two", slug="acme")


class MembershipModelTests(TestCase):
    def setUp(self):
        self.org = Organization.objects.create(name="Acme", slug="acme")
        self.user = get_user_model().objects.create_user(
            username="alice", password="pw"
        )

    def test_default_role_is_member(self):
        membership = Membership.objects.create(organization=self.org, user=self.user)
        self.assertEqual(membership.role, Membership.ROLE_MEMBER)
        self.assertIsNotNone(membership.created_at)

    def test_has_role_is_exact_match(self):
        membership = Membership.objects.create(
            organization=self.org, user=self.user, role=Membership.ROLE_ADMIN
        )
        self.assertTrue(membership.has_role(Membership.ROLE_ADMIN))
        self.assertFalse(membership.has_role(Membership.ROLE_OWNER))
        self.assertFalse(membership.has_role(Membership.ROLE_MEMBER))

    def test_at_least_respects_hierarchy(self):
        membership = Membership.objects.create(
            organization=self.org, user=self.user, role=Membership.ROLE_ADMIN
        )
        # admin is at least admin, member, and viewer
        self.assertTrue(membership.at_least(Membership.ROLE_ADMIN))
        self.assertTrue(membership.at_least(Membership.ROLE_MEMBER))
        self.assertTrue(membership.at_least(Membership.ROLE_VIEWER))
        # but not owner
        self.assertFalse(membership.at_least(Membership.ROLE_OWNER))

    def test_viewer_is_only_at_least_viewer(self):
        membership = Membership.objects.create(
            organization=self.org, user=self.user, role=Membership.ROLE_VIEWER
        )
        self.assertTrue(membership.at_least(Membership.ROLE_VIEWER))
        self.assertFalse(membership.at_least(Membership.ROLE_MEMBER))
        self.assertFalse(membership.at_least(Membership.ROLE_ADMIN))
        self.assertFalse(membership.at_least(Membership.ROLE_OWNER))

    def test_user_unique_per_organization(self):
        Membership.objects.create(organization=self.org, user=self.user)
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                Membership.objects.create(organization=self.org, user=self.user)

    def test_same_user_can_join_multiple_organizations(self):
        other_org = Organization.objects.create(name="Beta", slug="beta")
        Membership.objects.create(organization=self.org, user=self.user)
        Membership.objects.create(organization=other_org, user=self.user)
        self.assertEqual(self.user.memberships.count(), 2)
