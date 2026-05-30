from unittest import mock

from django.test import TestCase
from django.urls import reverse


class HealthEndpointTests(TestCase):
    def test_healthz_always_ok(self):
        resp = self.client.get(reverse('healthz'))
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), {"status": "ok"})

    def test_readyz_ok_when_db_reachable(self):
        resp = self.client.get(reverse('readyz'))
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), {"status": "ok"})

    def test_readyz_503_when_db_unreachable(self):
        with mock.patch(
            'doctorhide.health.connection.ensure_connection',
            side_effect=Exception('db down'),
        ):
            resp = self.client.get(reverse('readyz'))
        self.assertEqual(resp.status_code, 503)
        self.assertEqual(resp.json(), {"status": "unavailable"})
