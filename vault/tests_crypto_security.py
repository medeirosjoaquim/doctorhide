"""Cryptographic and zero-knowledge guarantees for the vault app.

Covers gaps left by tests.py: wrong-passphrase/salt/iteration key divergence,
verifier failure modes, ciphertext zero-knowledge, integrity (InvalidToken on
tampering / wrong key), and model-level isolation, uniqueness, and
update_or_create overwrite behaviour.
"""
import base64

from cryptography.fernet import Fernet, InvalidToken
from django.contrib.auth import get_user_model
from django.db import IntegrityError, transaction
from django.test import TestCase

from . import crypto
from .crypto import DEFAULT_ITERATIONS
from .models import Project, Secret

User = get_user_model()

PASSPHRASE = "correct-horse-battery"


def make_project(owner, name="prod"):
    salt = crypto.generate_salt()
    key = crypto.derive_key(PASSPHRASE, salt)
    project = Project.objects.create(
        owner=owner,
        public_id=Project.new_public_id(),
        name=name,
    )
    # ``project.default_environment`` is a property that does a fresh
    # query each call. Capture the env in a local so the salt/verifier
    # writes and the save are on the *same* Python instance; otherwise
    # the second call returns a different instance and the saved
    # values are the ones set on it (only the verifier, in this
    # shape), not the salt we want.
    env = project.default_environment
    env.salt = salt
    env.verifier = crypto.make_verifier(key)
    env.save(update_fields=["salt", "verifier"])
    return project, key


class KeyDerivationTests(TestCase):
    def test_wrong_passphrase_derives_different_key(self):
        salt = crypto.generate_salt()
        right = crypto.derive_key(PASSPHRASE, salt, iterations=1000)
        wrong = crypto.derive_key("not-it", salt, iterations=1000)
        self.assertNotEqual(right, wrong)

    def test_different_salt_derives_different_key(self):
        k1 = crypto.derive_key(PASSPHRASE, crypto.generate_salt(), iterations=1000)
        k2 = crypto.derive_key(PASSPHRASE, crypto.generate_salt(), iterations=1000)
        self.assertNotEqual(k1, k2)

    def test_different_iterations_derive_different_keys(self):
        salt = crypto.generate_salt()
        k1 = crypto.derive_key(PASSPHRASE, salt, iterations=1000)
        k2 = crypto.derive_key(PASSPHRASE, salt, iterations=2000)
        self.assertNotEqual(k1, k2)

    def test_default_iterations_matches_constant(self):
        salt = crypto.generate_salt()
        default = crypto.derive_key(PASSPHRASE, salt)
        explicit = crypto.derive_key(PASSPHRASE, salt, iterations=DEFAULT_ITERATIONS)
        self.assertEqual(default, explicit)
        self.assertEqual(DEFAULT_ITERATIONS, 600_000)

    def test_derived_key_is_valid_fernet_key(self):
        key = crypto.derive_key(PASSPHRASE, crypto.generate_salt(), iterations=1000)
        self.assertEqual(len(key), 44)
        token = Fernet(key).encrypt(b"ok")
        self.assertEqual(Fernet(key).decrypt(token), b"ok")


class SaltTests(TestCase):
    def test_generate_salt_length_and_randomness(self):
        s1 = crypto.generate_salt()
        s2 = crypto.generate_salt()
        self.assertEqual(len(s1), 24)
        self.assertNotEqual(s1, s2)
        self.assertEqual(len(base64.b64decode(s1)), 16)


class VerifierTests(TestCase):
    def setUp(self):
        self.salt = crypto.generate_salt()
        self.key = crypto.derive_key(PASSPHRASE, self.salt, iterations=1000)

    def test_verify_fails_for_wrong_key_without_raising(self):
        verifier = crypto.make_verifier(self.key)
        wrong = crypto.derive_key("nope", self.salt, iterations=1000)
        self.assertFalse(crypto.verify_key(wrong, verifier))

    def test_verify_fails_for_tampered_verifier(self):
        verifier = crypto.make_verifier(self.key)
        tampered = verifier[:-2] + ("AA" if verifier[-2:] != "AA" else "BB")
        self.assertFalse(crypto.verify_key(self.key, tampered))

    def test_verifier_leaks_no_passphrase_or_key(self):
        verifier = crypto.make_verifier(self.key)
        self.assertNotIn(PASSPHRASE, verifier)
        self.assertNotIn(self.key.decode(), verifier)

    def test_verifier_non_deterministic_but_both_validate(self):
        v1 = crypto.make_verifier(self.key)
        v2 = crypto.make_verifier(self.key)
        self.assertNotEqual(v1, v2)
        self.assertTrue(crypto.verify_key(self.key, v1))
        self.assertTrue(crypto.verify_key(self.key, v2))


class EncryptionZeroKnowledgeTests(TestCase):
    def setUp(self):
        self.salt = crypto.generate_salt()
        self.key = crypto.derive_key(PASSPHRASE, self.salt, iterations=1000)

    def test_ciphertext_is_not_plaintext(self):
        ct = crypto.encrypt(self.key, "super-secret-value")
        self.assertNotIn("super-secret-value", ct)

    def test_decrypt_with_wrong_key_raises_invalid_token(self):
        ct = crypto.encrypt(self.key, "s3cr3t")
        wrong = crypto.derive_key("other", self.salt, iterations=1000)
        with self.assertRaises(InvalidToken):
            crypto.decrypt(wrong, ct)

    def test_decrypt_tampered_ciphertext_raises_invalid_token(self):
        ct = crypto.encrypt(self.key, "s3cr3t")
        tampered = ct[:-2] + ("AA" if ct[-2:] != "AA" else "BB")
        with self.assertRaises(InvalidToken):
            crypto.decrypt(self.key, tampered)

    def test_same_plaintext_encrypts_to_different_ciphertext(self):
        c1 = crypto.encrypt(self.key, "repeat-me")
        c2 = crypto.encrypt(self.key, "repeat-me")
        self.assertNotEqual(c1, c2)
        self.assertEqual(crypto.decrypt(self.key, c1), "repeat-me")
        self.assertEqual(crypto.decrypt(self.key, c2), "repeat-me")

    def test_roundtrip_edge_values(self):
        for value in ["", "   ", "café ☕ ñ 漢字", "line1\nline2\t"]:
            ct = crypto.encrypt(self.key, value)
            self.assertEqual(crypto.decrypt(self.key, ct), value)


class ProjectZeroKnowledgeModelTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="alice", password="pw-alice")
        self.salt = crypto.generate_salt()
        self.key = crypto.derive_key(PASSPHRASE, self.salt, iterations=1000)

    def test_project_has_no_passphrase_field(self):
        """Project is a container (Week 8 Phase 1). The cryptography lives
        on Environment, so the Project model itself must not carry
        ``passphrase``/``salt``/``verifier``/``iterations`` as real DB
        columns. (The shim properties that delegate to
        ``Project.default_environment`` are Python-level, not DB
        columns, and so do not show up in ``_meta.get_fields()``.)"""
        field_names = {f.name for f in Project._meta.get_fields()}
        self.assertNotIn("passphrase", field_names)
        self.assertNotIn("salt", field_names)
        self.assertNotIn("iterations", field_names)
        self.assertNotIn("verifier", field_names)

    def test_environment_has_no_passphrase_field(self):
        """The crypto boundary moved to Environment in Week 8 Phase 1.
        Same zero-knowledge contract now applies to the Environment
        model."""
        from .models import Environment

        field_names = {f.name for f in Environment._meta.get_fields()}
        self.assertNotIn("passphrase", field_names)
        self.assertIn("salt", field_names)
        self.assertIn("iterations", field_names)
        self.assertIn("verifier", field_names)

    def test_passphrase_absent_from_all_persisted_columns(self):
        p = make_project(self.user, name="proj")[0]
        # Project (the container) and Environment (the crypto) — the
        # passphrase must not appear in *either* set of persisted
        # columns.
        for model in (p, p.default_environment):
            for field in model._meta.fields:
                value = getattr(model, field.attname)
                if isinstance(value, str):
                    self.assertNotIn(PASSPHRASE, value)

    def test_stored_verifier_validates_correct_and_rejects_wrong(self):
        p = make_project(self.user, name="proj")[0]
        p.refresh_from_db()
        env = p.default_environment
        env.refresh_from_db()
        # Re-derive the test's known passphrase against the env's
        # *actual* iterations (the factory used the production default
        # of 600_000, not the test setUp's 1000).
        correct = crypto.derive_key(PASSPHRASE, env.salt, iterations=env.iterations)
        wrong = crypto.derive_key("WRONG", env.salt, iterations=env.iterations)
        self.assertTrue(crypto.verify_key(correct, env.verifier))
        self.assertFalse(crypto.verify_key(wrong, env.verifier))

    def test_iterations_defaults_to_constant(self):
        p = make_project(self.user, name="proj")[0]
        env = p.default_environment
        env.refresh_from_db()
        self.assertEqual(env.iterations, 600_000)


class ProjectUniquenessTests(TestCase):
    def setUp(self):
        self.alice = User.objects.create_user(username="alice", password="pw-1")
        self.bob = User.objects.create_user(username="bob", password="pw-2")

    def test_duplicate_name_same_owner_rejected(self):
        make_project(self.alice, name="dup")
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                make_project(self.alice, name="dup")

    def test_same_name_different_owner_allowed(self):
        make_project(self.alice, name="shared")
        other, _ = make_project(self.bob, name="shared")
        self.assertEqual(Project.objects.filter(name="shared").count(), 2)
        self.assertEqual(other.owner, self.bob)


class SecretLifecycleTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="alice", password="pw-1")
        self.p1, self.key = make_project(self.user, name="p1")
        self.p2, _ = make_project(self.user, name="p2")

    def test_duplicate_key_same_project_rejected(self):
        Secret.objects.create(project=self.p1, key="API", ciphertext="x")
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                Secret.objects.create(project=self.p1, key="API", ciphertext="y")

    def test_same_key_different_project_allowed(self):
        Secret.objects.create(project=self.p1, key="API", ciphertext="x")
        Secret.objects.create(project=self.p2, key="API", ciphertext="y")
        self.assertEqual(Secret.objects.filter(key="API").count(), 2)

    def test_update_or_create_overwrites_ciphertext_in_place(self):
        old_ct = crypto.encrypt(self.key, "old-value")
        new_ct = crypto.encrypt(self.key, "new-value")
        Secret.objects.update_or_create(
            project=self.p1, key="TOKEN", defaults={"ciphertext": old_ct}
        )
        Secret.objects.update_or_create(
            project=self.p1, key="TOKEN", defaults={"ciphertext": new_ct}
        )
        rows = Secret.objects.filter(project=self.p1, key="TOKEN")
        self.assertEqual(rows.count(), 1)
        self.assertEqual(crypto.decrypt(self.key, rows.get().ciphertext), "new-value")
