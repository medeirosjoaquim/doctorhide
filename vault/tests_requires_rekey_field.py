"""Model-level tests for the ``requires_rekey`` flag.

After Week 8 Phase 1, the flag lives on ``Environment``, not
``Project``. Pre-Week-8, this file tested ``Project.requires_rekey``;
the same shape of contract is now pinned against
``Environment.requires_rekey``. The view-level behaviour (the rekey
view itself, ``project_unlock`` redirects, the template banner) is
covered by ``vault/tests_rekey.py`` (which is also being adapted to
env-scoped patterns in Phase 3).
"""

from __future__ import annotations

from django.contrib.auth import get_user_model
from django.test import TestCase

from . import crypto
from .models import Environment, Project

User = get_user_model()


def _make_project(user, **overrides):
    """Create a Project + a seeded default Environment with crypto set up.

    Mirrors the helpers in the other test files; kept here so the
    requires_rekey contract tests do not depend on a sibling helper.
    """
    salt = crypto.generate_salt()
    key = crypto.derive_key("correct-horse-battery", salt)
    from organizations.models import personal_organization

    org = personal_organization(user)
    defaults = {
        "owner": user,
        "organization": org,
        "public_id": Project.new_public_id(),
        "name": "p",
    }
    defaults.update(overrides)
    project = Project.objects.create(**defaults)
    env = project.default_environment
    env.salt = salt
    env.verifier = crypto.make_verifier(key)
    env.save(update_fields=["salt", "verifier"])
    return project


class EnvironmentRequiresRekeyFieldTests(TestCase):
    def test_default_value_is_false(self):
        user = User.objects.create_user(username="alice", password="pw")
        project = _make_project(user)
        env = project.default_environment
        env.refresh_from_db()
        self.assertFalse(env.requires_rekey)

    def test_setting_true_round_trips_through_db(self):
        user = User.objects.create_user(username="alice", password="pw")
        project = _make_project(user)
        env = project.default_environment
        env.requires_rekey = True
        env.save(update_fields=["requires_rekey"])
        env.refresh_from_db()
        self.assertTrue(env.requires_rekey)

    def test_queryable_by_value(self):
        user = User.objects.create_user(username="alice", password="pw")
        flagged_project = _make_project(user, name="flagged")
        clean_project = _make_project(user, name="clean")
        # Note: ``default_environment`` is a property that does a fresh
        # query each call. Capture the env in a local first so the
        # mutation and the save are on the *same* Python instance.
        flagged_env = flagged_project.default_environment
        flagged_env.requires_rekey = True
        flagged_env.save(update_fields=["requires_rekey"])

        self.assertEqual(
            list(
                Environment.objects.filter(requires_rekey=True).values_list(
                    "id", flat=True
                )
            ),
            [flagged_env.id],
        )
        self.assertEqual(
            list(
                Environment.objects.filter(requires_rekey=False).values_list(
                    "id", flat=True
                )
            ),
            [clean_project.default_environment.id],
        )
        self.assertEqual(
            list(
                Environment.objects.filter(requires_rekey=False).values_list(
                    "id", flat=True
                )
            ),
            [clean_project.default_environment.id],
        )

    def test_clearing_flag_after_rekey_is_persisted(self):
        """The rekey view flips the flag to False at the end of a successful
        rotation. This test pins that the *flag* part of that write actually
        hits the database (and is not just an in-memory mutation)."""
        user = User.objects.create_user(username="alice", password="pw")
        project = _make_project(user)
        env = project.default_environment
        env.requires_rekey = True
        env.save(update_fields=["requires_rekey"])
        self.assertTrue(
            Environment.objects.filter(pk=env.pk, requires_rekey=True).exists()
        )
        env.requires_rekey = False
        env.save(update_fields=["requires_rekey"])
        self.assertFalse(
            Environment.objects.filter(pk=env.pk, requires_rekey=True).exists()
        )

    def test_creating_with_explicit_true_is_honoured(self):
        """The model accepts ``requires_rekey=True`` at creation time (the
        incident response path sets it that way via ``update()`` on an
        existing env, but the field must work on create too)."""
        user = User.objects.create_user(username="alice", password="pw")
        project = _make_project(user)
        env = project.default_environment
        env.requires_rekey = True
        env.save()
        self.assertTrue(env.requires_rekey)
        env.refresh_from_db()
        self.assertTrue(env.requires_rekey)

    def test_project_shim_reflects_env_flag(self):
        """The read-only ``Project.requires_rekey`` shim must surface the
        default env's flag value, so the dozens of read-only call sites
        in views/tests (that still say ``project.requires_rekey``) keep
        working through Phase 3."""
        user = User.objects.create_user(username="alice", password="pw")
        project = _make_project(user)
        self.assertFalse(project.requires_rekey)

        env = project.default_environment
        env.requires_rekey = True
        env.save(update_fields=["requires_rekey"])
        # The shim is a property — it reads the env fresh each time.
        self.assertTrue(project.requires_rekey)
