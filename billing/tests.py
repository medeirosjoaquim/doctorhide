from django.db import IntegrityError
from django.test import TestCase

from organizations.models import Organization
from billing.models import Plan, Subscription


class SeededPlansTests(TestCase):
    """The data migration seeds Free and Pro plans."""

    def test_free_plan_seeded(self):
        free = Plan.objects.get(slug="free")
        self.assertEqual(free.name, "Free")
        self.assertEqual(free.price_cents, 0)
        self.assertEqual(free.interval, Plan.Interval.MONTH)
        self.assertEqual(free.limits["max_projects"], 3)
        self.assertEqual(free.limits["max_secrets"], 50)
        self.assertEqual(free.limits["max_seats"], 1)
        self.assertEqual(free.limits["max_api_keys"], 2)

    def test_pro_plan_seeded(self):
        pro = Plan.objects.get(slug="pro")
        self.assertEqual(pro.name, "Pro")
        self.assertEqual(pro.price_cents, 2900)
        self.assertIn("max_seats", pro.limits)


class SubscriptionTests(TestCase):
    """Subscription is one-to-one with an organization."""

    def setUp(self):
        self.org = Organization.objects.create(name="Acme", slug="acme")
        self.free = Plan.objects.get(slug="free")

    def test_create_subscription_defaults_active(self):
        sub = Subscription.objects.create(organization=self.org, plan=self.free)
        self.assertEqual(sub.status, Subscription.Status.ACTIVE)
        self.assertEqual(self.org.subscription, sub)

    def test_one_subscription_per_org(self):
        Subscription.objects.create(organization=self.org, plan=self.free)
        with self.assertRaises(IntegrityError):
            Subscription.objects.create(organization=self.org, plan=self.free)
