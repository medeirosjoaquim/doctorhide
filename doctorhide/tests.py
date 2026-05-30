import importlib
import os
from unittest import mock

from django.test import SimpleTestCase

import doctorhide.settings as dh_settings


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
