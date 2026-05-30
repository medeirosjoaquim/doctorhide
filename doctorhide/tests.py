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
