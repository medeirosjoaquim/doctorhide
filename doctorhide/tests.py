import importlib
import os
from unittest import mock

from django.core.exceptions import ImproperlyConfigured
from django.test import SimpleTestCase

import doctorhide.settings as dh_settings


class SecretKeyEnvTests(SimpleTestCase):
    def tearDown(self):
        importlib.reload(dh_settings)

    def test_secret_key_from_env(self):
        with mock.patch.dict(os.environ, {'SECRET_KEY': 'env-provided-key'}):
            self.assertEqual(importlib.reload(dh_settings).SECRET_KEY, 'env-provided-key')

    def test_secret_key_falls_back_to_dev_when_unset(self):
        env = {k: v for k, v in os.environ.items() if k not in ('SECRET_KEY', 'DJANGO_ENV')}
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertEqual(
                importlib.reload(dh_settings).SECRET_KEY,
                dh_settings._DEV_SECRET_KEY,
            )

    def test_secret_key_required_in_production(self):
        env = {k: v for k, v in os.environ.items() if k != 'SECRET_KEY'}
        env['DJANGO_ENV'] = 'production'
        with mock.patch.dict(os.environ, env, clear=True):
            with self.assertRaises(ImproperlyConfigured):
                importlib.reload(dh_settings)


class DebugEnvTests(SimpleTestCase):
    def _reload_debug(self):
        return importlib.reload(dh_settings).DEBUG

    def tearDown(self):
        importlib.reload(dh_settings)

    def test_debug_defaults_false_when_unset(self):
        env = {k: v for k, v in os.environ.items() if k != 'DJANGO_DEBUG'}
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertFalse(self._reload_debug())

    def test_debug_truthy_values_enable(self):
        for value in ('1', 'true', 'True', 'yes', 'YES'):
            with mock.patch.dict(os.environ, {'DJANGO_DEBUG': value}):
                self.assertTrue(self._reload_debug(), value)

    def test_debug_falsy_values_disable(self):
        for value in ('0', 'false', 'no', ''):
            with mock.patch.dict(os.environ, {'DJANGO_DEBUG': value}):
                self.assertFalse(self._reload_debug(), value)


class DatabaseConnectionTuningTests(SimpleTestCase):
    def tearDown(self):
        importlib.reload(dh_settings)

    def test_conn_max_age_defaults_to_zero_in_dev(self):
        env = {k: v for k, v in os.environ.items() if k != 'DB_CONN_MAX_AGE'}
        with mock.patch.dict(os.environ, env, clear=True):
            settings = importlib.reload(dh_settings)
            self.assertEqual(settings.DATABASES['default']['CONN_MAX_AGE'], 0)

    def test_conn_max_age_from_env(self):
        with mock.patch.dict(os.environ, {'DB_CONN_MAX_AGE': '600'}):
            settings = importlib.reload(dh_settings)
            self.assertEqual(settings.DATABASES['default']['CONN_MAX_AGE'], 600)

    def test_conn_max_age_supports_persistent_connections(self):
        with mock.patch.dict(os.environ, {'DB_CONN_MAX_AGE': '-1'}):
            settings = importlib.reload(dh_settings)
            self.assertEqual(settings.DATABASES['default']['CONN_MAX_AGE'], -1)

    def test_conn_health_checks_defaults_false_in_dev(self):
        env = {k: v for k, v in os.environ.items() if k != 'DB_CONN_HEALTH_CHECKS'}
        with mock.patch.dict(os.environ, env, clear=True):
            settings = importlib.reload(dh_settings)
            self.assertFalse(settings.DATABASES['default']['CONN_HEALTH_CHECKS'])

    def test_conn_health_checks_enabled_by_truthy_values(self):
        for value in ('1', 'true', 'yes'):
            with mock.patch.dict(os.environ, {'DB_CONN_HEALTH_CHECKS': value}):
                settings = importlib.reload(dh_settings)
                self.assertTrue(settings.DATABASES['default']['CONN_HEALTH_CHECKS'], value)

    def test_conn_health_checks_disabled_by_falsy_values(self):
        for value in ('0', 'false', 'no', ''):
            with mock.patch.dict(os.environ, {'DB_CONN_HEALTH_CHECKS': value}):
                settings = importlib.reload(dh_settings)
                self.assertFalse(settings.DATABASES['default']['CONN_HEALTH_CHECKS'], value)


class SessionEngineTests(SimpleTestCase):
    def tearDown(self):
        importlib.reload(dh_settings)

    def test_session_engine_defaults_to_db_backend(self):
        env = {k: v for k, v in os.environ.items() if k != 'SESSION_ENGINE'}
        with mock.patch.dict(os.environ, env, clear=True):
            settings = importlib.reload(dh_settings)
            self.assertEqual(settings.SESSION_ENGINE, 'django.contrib.sessions.backends.db')

    def test_session_engine_from_env(self):
        with mock.patch.dict(os.environ, {'SESSION_ENGINE': 'django.contrib.sessions.backends.cache'}):
            settings = importlib.reload(dh_settings)
            self.assertEqual(settings.SESSION_ENGINE, 'django.contrib.sessions.backends.cache')

    def test_session_engine_can_be_overridden_for_redis(self):
        with mock.patch.dict(os.environ, {'SESSION_ENGINE': 'django_redis.cache.SessionStore'}):
            settings = importlib.reload(dh_settings)
            self.assertEqual(settings.SESSION_ENGINE, 'django_redis.cache.SessionStore')
