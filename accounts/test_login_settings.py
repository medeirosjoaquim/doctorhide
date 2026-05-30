from django.conf import settings
from django.test import TestCase
from django.urls import reverse


class LoginSettingsTests(TestCase):
    def test_login_url_points_to_accounts_login(self):
        self.assertEqual(settings.LOGIN_URL, "accounts:login")
        self.assertTrue(reverse(settings.LOGIN_URL))

    def test_login_redirect_url_points_to_projects(self):
        self.assertEqual(settings.LOGIN_REDIRECT_URL, "vault:projects")
        self.assertTrue(reverse(settings.LOGIN_REDIRECT_URL))
