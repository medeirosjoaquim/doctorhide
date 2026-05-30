import importlib
import os
from unittest import mock

import django
from django.test import SimpleTestCase


def _reload_settings():
    import doctorhide.settings as settings_module

    importlib.reload(settings_module)
    return settings_module


def _restore_settings():
    import doctorhide.settings as settings_module

    importlib.reload(settings_module)
    django.setup()


class LoggingSettingsTests(SimpleTestCase):
    def tearDown(self):
        _restore_settings()

    def test_default_log_level_is_info(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop('LOG_LEVEL', None)
            settings_module = _reload_settings()
            self.assertEqual(settings_module.LOG_LEVEL, 'INFO')
            self.assertEqual(settings_module.LOGGING['root']['level'], 'INFO')

    def test_console_handler_present(self):
        settings_module = _reload_settings()
        handlers = settings_module.LOGGING['handlers']
        self.assertIn('console', handlers)
        self.assertEqual(handlers['console']['class'], 'logging.StreamHandler')
        self.assertEqual(settings_module.LOGGING['root']['handlers'], ['console'])

    def test_log_level_from_env(self):
        with mock.patch.dict(os.environ, {'LOG_LEVEL': 'debug'}, clear=False):
            settings_module = _reload_settings()
            self.assertEqual(settings_module.LOG_LEVEL, 'DEBUG')
            self.assertEqual(settings_module.LOGGING['root']['level'], 'DEBUG')
