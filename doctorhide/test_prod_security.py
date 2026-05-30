"""Tests for production-only HTTPS hardening settings.

These settings must be active only when DJANGO_ENV=production so that the
test suite and local development keep working over plain HTTP.
"""
from django.conf import settings as live_settings
from django.test import SimpleTestCase


class ProdSecuritySettingsTest(SimpleTestCase):
    def test_security_flags_off_in_test_env(self):
        # The suite runs without DJANGO_ENV=production, so the hardening must
        # be inactive (otherwise local/test HTTP traffic would be redirected).
        self.assertFalse(getattr(live_settings, 'SECURE_SSL_REDIRECT', False))
        self.assertFalse(getattr(live_settings, 'SECURE_HSTS_SECONDS', 0))
        self.assertFalse(
            getattr(live_settings, 'SESSION_COOKIE_SECURE', False))
        self.assertFalse(getattr(live_settings, 'CSRF_COOKIE_SECURE', False))
        self.assertIsNone(
            getattr(live_settings, 'SECURE_PROXY_SSL_HEADER', None))

    def test_security_flags_on_when_production_env(self):
        # Re-execute the settings module body in an isolated namespace with
        # DJANGO_ENV=production so the gated block runs, without mutating the
        # live (already-configured) settings module.
        import os

        path = os.path.join(os.path.dirname(__file__), 'settings.py')
        with open(path) as fh:
            source = fh.read()

        ns = {'__file__': path, '__name__': 'doctorhide._prod_settings_probe'}
        env_backup = os.environ.get('DJANGO_ENV')
        secret_backup = os.environ.get('SECRET_KEY')
        os.environ['DJANGO_ENV'] = 'production'
        os.environ['SECRET_KEY'] = 'x' * 50
        try:
            exec(compile(source, path, 'exec'), ns)
        finally:
            if env_backup is None:
                os.environ.pop('DJANGO_ENV', None)
            else:
                os.environ['DJANGO_ENV'] = env_backup
            if secret_backup is None:
                os.environ.pop('SECRET_KEY', None)
            else:
                os.environ['SECRET_KEY'] = secret_backup

        self.assertTrue(ns['SECURE_SSL_REDIRECT'])
        self.assertEqual(ns['SECURE_HSTS_SECONDS'], 31536000)
        self.assertTrue(ns['SECURE_HSTS_INCLUDE_SUBDOMAINS'])
        self.assertTrue(ns['SESSION_COOKIE_SECURE'])
        self.assertTrue(ns['CSRF_COOKIE_SECURE'])
        self.assertEqual(
            ns['SECURE_PROXY_SSL_HEADER'],
            ('HTTP_X_FORWARDED_PROTO', 'https'),
        )
