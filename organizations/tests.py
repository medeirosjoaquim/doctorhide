from django.db import IntegrityError
from django.test import TestCase

from .models import Organization


class OrganizationModelTests(TestCase):
    def test_create_organization(self):
        org = Organization.objects.create(name="Acme", slug="acme")
        self.assertEqual(str(org), "Acme")
        self.assertIsNotNone(org.created_at)

    def test_slug_is_unique(self):
        Organization.objects.create(name="Acme", slug="acme")
        with self.assertRaises(IntegrityError):
            Organization.objects.create(name="Acme Two", slug="acme")
