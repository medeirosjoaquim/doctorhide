import importlib
import os
from unittest import mock

from django.test import SimpleTestCase


def _load_allowed_hosts(env):
    """Import the settings module in a fresh namespace under the given env.

    A separate import (not a reload of the live ``doctorhide.settings``) is used
    so the running test suite's configured settings are never mutated.
    """
    spec = importlib.util.find_spec('doctorhide.settings')
    module = importlib.util.module_from_spec(spec)
    with mock.patch.dict(os.environ, env, clear=False):
        os.environ.pop('ALLOWED_HOSTS', None)
        if 'ALLOWED_HOSTS' in env:
            os.environ['ALLOWED_HOSTS'] = env['ALLOWED_HOSTS']
        spec.loader.exec_module(module)
    return list(module.ALLOWED_HOSTS)


class AllowedHostsFromEnvTests(SimpleTestCase):
    def test_default_dev_hosts(self):
        self.assertEqual(
            _load_allowed_hosts({}),
            ['127.0.0.1', 'localhost'],
        )

    def test_parses_comma_separated_env(self):
        self.assertEqual(
            _load_allowed_hosts({'ALLOWED_HOSTS': 'example.com, api.example.com'}),
            ['example.com', 'api.example.com'],
        )

    def test_blank_entries_are_dropped(self):
        self.assertEqual(
            _load_allowed_hosts({'ALLOWED_HOSTS': 'example.com,,  ,foo.com'}),
            ['example.com', 'foo.com'],
        )
