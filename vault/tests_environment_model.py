"""Model-level tests for the Week 8 Phase 1 Environment model.

These tests pin the contract:

* a default ``Environment`` is auto-seeded on Project create (via
  ``post_save`` signal in ``vault/signals.py``);
* the env carries the cryptography that previously lived on Project
  (salt, iterations, verifier, requires_rekey);
* the Project's read-only shim properties (project.salt etc.)
  delegate to ``Project.default_environment`` and return the same
  values;
* slug/name uniqueness within a project is enforced;
* the env-to-project lookup is the canonical reverse FK
  (``project.environments.all()``);
* ``Project.default_environment`` raises ``Environment.DoesNotExist``
  when the signal has not run (the rare direct-ORM path).
"""

from __future__ import annotations

from django.contrib.auth import get_user_model
from django.db import IntegrityError
from django.test import TestCase

from . import crypto
from .models import Environment, Project

User = get_user_model()

PASSPHRASE = "correct-horse-battery"


def _make_owner(username="alice"):
    return User.objects.create_user(username=username, password="pw")


class EnvironmentModelTests(TestCase):
    def test_project_create_auto_seeds_default_environment(self):
        """The ``post_save`` signal must create exactly one default
        Environment when a new Project is created."""
        owner = _make_owner()
        self.assertEqual(Environment.objects.count(), 0)
        project = Project.objects.create(
            owner=owner,
            public_id=Project.new_public_id(),
            name="p",
        )
        envs = list(project.environments.all())
        self.assertEqual(len(envs), 1)
        seeded = envs[0]
        self.assertEqual(seeded.slug, Environment.default_seeded_slug())
        self.assertEqual(seeded.name, Environment.default_seeded_name())
        self.assertFalse(seeded.requires_rekey)

    def test_resave_does_not_clobber_existing_env_crypto(self):
        """Saving an existing Project must not overwrite the env's crypto
        (the signal is ``created``-guarded)."""
        owner = _make_owner()
        project = Project.objects.create(
            owner=owner,
            public_id=Project.new_public_id(),
            name="p",
        )
        env = project.default_environment
        env.salt = "manually-set-salt"
        env.verifier = "manually-set-verifier"
        env.save(update_fields=["salt", "verifier"])

        # Re-save the project (e.g. name change) and confirm the env's
        # manually-set crypto is preserved.
        project.name = "p2"
        project.save()
        env.refresh_from_db()
        self.assertEqual(env.salt, "manually-set-salt")
        self.assertEqual(env.verifier, "manually-set-verifier")

    def test_default_environment_returns_seeded_env(self):
        owner = _make_owner()
        project = Project.objects.create(
            owner=owner, public_id=Project.new_public_id(), name="p"
        )
        env_via_property = project.default_environment
        env_via_fk = project.environments.get(slug="default")
        self.assertEqual(env_via_property.pk, env_via_fk.pk)

    def test_project_shim_properties_delegate_to_default_environment(self):
        """``project.salt``/``.iterations``/``.verifier``/``.requires_rekey``
        are read-only shims that return the default env's values. Pin the
        delegation so the dozens of read-only call sites in views/tests
        keep working through the multi-phase refactor."""
        owner = _make_owner()
        project = Project.objects.create(
            owner=owner, public_id=Project.new_public_id(), name="p"
        )
        # The signal seeded the env with random crypto; the shim must
        # surface the same values.
        env = project.default_environment
        self.assertEqual(project.salt, env.salt)
        self.assertEqual(project.iterations, env.iterations)
        self.assertEqual(project.verifier, env.verifier)
        self.assertEqual(project.requires_rekey, env.requires_rekey)

    def test_shim_reflects_subsequent_env_writes(self):
        """If the env's crypto is updated after the project is created
        (the rekey flow writes here, for example), the shim must reflect
        the new values on the next read."""
        owner = _make_owner()
        project = Project.objects.create(
            owner=owner, public_id=Project.new_public_id(), name="p"
        )
        env = project.default_environment
        env.requires_rekey = True
        env.save(update_fields=["requires_rekey"])
        # The shim is a property, so it reads the env fresh each time.
        self.assertTrue(project.requires_rekey)

    def test_slug_uniqueness_within_project(self):
        owner = _make_owner()
        project = Project.objects.create(
            owner=owner, public_id=Project.new_public_id(), name="p"
        )
        # First env (default) is seeded by the signal. A second env with
        # the same slug in the same project must fail.
        salt = crypto.generate_salt()
        with self.assertRaises(IntegrityError):
            Environment.objects.create(
                project=project,
                name="Other",
                slug=Environment.default_seeded_slug(),
                salt=salt,
                verifier=crypto.make_verifier(crypto.derive_key("x", salt)),
            )

    def test_name_uniqueness_within_project(self):
        owner = _make_owner()
        project = Project.objects.create(
            owner=owner, public_id=Project.new_public_id(), name="p"
        )
        salt = crypto.generate_salt()
        with self.assertRaises(IntegrityError):
            Environment.objects.create(
                project=project,
                name=Environment.default_seeded_name(),
                slug="other",
                salt=salt,
                verifier=crypto.make_verifier(crypto.derive_key("x", salt)),
            )

    def test_same_slug_allowed_across_different_projects(self):
        """The uniqueness is per-project, not global. Two projects can
        both have an env named ``default``."""
        owner = _make_owner()
        p1 = Project.objects.create(
            owner=owner, public_id=Project.new_public_id(), name="p1"
        )
        p2 = Project.objects.create(
            owner=owner, public_id=Project.new_public_id(), name="p2"
        )
        # Both projects' signals have already seeded a default env.
        self.assertEqual(p1.environments.count(), 1)
        self.assertEqual(p2.environments.count(), 1)
        self.assertEqual(
            p1.environments.first().slug, p2.environments.first().slug
        )

    def test_env_can_hold_custom_crypto(self):
        """The env must accept a real salt/verifier pair derived from a
        known passphrase, and that pair must verify with
        ``crypto.verify_key``."""
        owner = _make_owner()
        project = Project.objects.create(
            owner=owner, public_id=Project.new_public_id(), name="p"
        )
        salt = crypto.generate_salt()
        key = crypto.derive_key(PASSPHRASE, salt)
        env = project.default_environment
        env.salt = salt
        env.verifier = crypto.make_verifier(key)
        env.save(update_fields=["salt", "verifier"])

        derived = crypto.derive_key(PASSPHRASE, env.salt)
        self.assertTrue(crypto.verify_key(derived, env.verifier))

    def test_multiple_envs_can_coexist_on_one_project(self):
        owner = _make_owner()
        project = Project.objects.create(
            owner=owner, public_id=Project.new_public_id(), name="p"
        )
        # Add two more envs; the default was already seeded.
        for slug, name in [("staging", "Staging"), ("prod", "Production")]:
            salt = crypto.generate_salt()
            Environment.objects.create(
                project=project,
                name=name,
                slug=slug,
                salt=salt,
                verifier=crypto.make_verifier(crypto.derive_key("k", salt)),
            )
        self.assertEqual(
            list(project.environments.values_list("slug", flat=True)),
            ["default", "prod", "staging"],  # ordered by Meta.ordering
        )

    def test_cascade_delete_with_project(self):
        """Deleting a project cascades to its envs (CASCADE on FK)."""
        owner = _make_owner()
        project = Project.objects.create(
            owner=owner, public_id=Project.new_public_id(), name="p"
        )
        self.assertEqual(Environment.objects.filter(project=project).count(), 1)
        project.delete()
        self.assertEqual(Environment.objects.count(), 0)

    def test_default_environment_does_not_exist_when_manually_deleted(self):
        """The shim must not silently return ``None`` if the env is gone
        (e.g. a buggy cleanup script wiped it). The exception lets the
        caller decide what to do rather than guessing."""
        owner = _make_owner()
        project = Project.objects.create(
            owner=owner, public_id=Project.new_public_id(), name="p"
        )
        project.default_environment.delete()
        with self.assertRaises(Environment.DoesNotExist):
            _ = project.default_environment


class EnvironmentCryptoFieldTests(TestCase):
    """The crypto fields on Environment are the new encryption boundary.
    Pin their defaults and shape so the shape cannot drift unnoticed."""

    def test_default_iterations_is_pbkdf2_default(self):
        owner = _make_owner()
        project = Project.objects.create(
            owner=owner, public_id=Project.new_public_id(), name="p"
        )
        env = project.default_environment
        self.assertEqual(env.iterations, crypto.DEFAULT_ITERATIONS)

    def test_requires_rekey_defaults_to_false(self):
        owner = _make_owner()
        project = Project.objects.create(
            owner=owner, public_id=Project.new_public_id(), name="p"
        )
        env = project.default_environment
        self.assertFalse(env.requires_rekey)

    def test_string_representation_includes_project_and_slug(self):
        owner = _make_owner()
        project = Project.objects.create(
            owner=owner, public_id=Project.new_public_id(), name="myapp"
        )
        env = project.default_environment
        self.assertEqual(str(env), f"myapp/{Environment.default_seeded_slug()}")

    def test_default_seeded_helpers_are_stable(self):
        """The helper constants must not drift, since Phase 3's view code
        will rely on them when expanding the seed to development/staging/
        production."""
        self.assertEqual(Environment.default_seeded_slug(), "default")
        self.assertEqual(Environment.default_seeded_name(), "Default")
