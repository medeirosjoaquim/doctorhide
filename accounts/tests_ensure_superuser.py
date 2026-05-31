from unittest import mock

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase

User = get_user_model()


class EnsureSuperuserCommandTests(TestCase):
    def test_creates_superuser_from_env(self):
        with mock.patch.dict(
            "os.environ",
            {"DJANGO_SUPERUSER_USERNAME": "root", "DJANGO_SUPERUSER_PASSWORD": "pw-123-secret"},
        ):
            call_command("ensure_superuser")
        user = User.objects.get(username="root")
        self.assertTrue(user.is_superuser)
        self.assertTrue(user.is_staff)
        self.assertTrue(user.check_password("pw-123-secret"))

    def test_defaults_username_to_admin(self):
        env = {k: v for k, v in __import__("os").environ.items() if not k.startswith("DJANGO_SUPERUSER_")}
        env["DJANGO_SUPERUSER_PASSWORD"] = "pw-123-secret"
        with mock.patch.dict("os.environ", env, clear=True):
            call_command("ensure_superuser")
        self.assertTrue(User.objects.filter(username="admin", is_superuser=True).exists())

    def test_is_idempotent(self):
        env = {"DJANGO_SUPERUSER_USERNAME": "root", "DJANGO_SUPERUSER_PASSWORD": "pw-123-secret"}
        with mock.patch.dict("os.environ", env):
            call_command("ensure_superuser")
            call_command("ensure_superuser")
        self.assertEqual(User.objects.filter(username="root").count(), 1)

    def test_errors_without_password(self):
        env = {k: v for k, v in __import__("os").environ.items() if not k.startswith("DJANGO_SUPERUSER_")}
        with mock.patch.dict("os.environ", env, clear=True):
            with self.assertRaises(CommandError):
                call_command("ensure_superuser")
        self.assertFalse(User.objects.filter(is_superuser=True).exists())
