import hashlib
import hmac
import secrets

from django.conf import settings
from django.db import models
from django.utils import timezone

from .crypto import DEFAULT_ITERATIONS

API_KEY_PREFIX = "dhk_"  # doctorhide project key
PUBLIC_ID_BYTES = 8
SECRET_BYTES = 32


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


class Project(models.Model):
    """A namespace of secrets, encrypted under a passphrase the server never stores.

    `salt` and `verifier` let a later-supplied passphrase derive the same key and
    be checked for correctness; the passphrase itself is never persisted.
    """

    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="projects"
    )
    organization = models.ForeignKey(
        "organizations.Organization",
        on_delete=models.CASCADE,
        related_name="projects",
    )
    public_id = models.CharField(max_length=24, unique=True, db_index=True)
    name = models.CharField(max_length=100)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    # Lets DRF treat an authenticated project (via API key) as a principal.
    is_authenticated = True
    is_anonymous = False

    class Meta:
        unique_together = ("owner", "name")

    def __str__(self):
        return self.name

    def save(self, *args, **kwargs):
        # Every project belongs to an organization; fall back to the owner's
        # personal organization when one wasn't supplied (e.g. direct ORM
        # creation in tests).
        if self.organization_id is None and self.owner_id is not None:
            from organizations.models import personal_organization

            self.organization = personal_organization(self.owner)
        super().save(*args, **kwargs)

    @staticmethod
    def new_public_id() -> str:
        return "proj_" + secrets.token_hex(PUBLIC_ID_BYTES)

    # ------------------------------------------------------------------
    # Environment (Week 8 Phase 1) — the cryptography lives on Environment,
    # not Project. These four read-only properties are a *temporary shim*
    # that delegates to the project's default environment, so the dozens
    # of call sites that read project.salt / project.verifier / etc. keep
    # working during the multi-phase refactor. Phase 3 removes these shims
    # when views and tests are rewritten to take an ``env_slug``.
    # ------------------------------------------------------------------

    @property
    def default_environment(self) -> "Environment":
        """Return the project's seeded ``default`` environment.

        Auto-created by a ``post_save`` signal on Project (see
        ``vault/signals.py``), so this should never raise for a project
        that came through ``Project.objects.save()``. Direct ORM
        ``Project()`` + ``.save()`` paths go through the signal; direct
        ``Project.objects.create(salt=..., verifier=...)`` patterns
        pre-date Week 8 and are addressed in Phase 6 (test rewrite).
        """
        return self.environments.get(slug="default")

    @property
    def salt(self) -> str:
        return self.default_environment.salt

    @property
    def iterations(self) -> int:
        return self.default_environment.iterations

    @property
    def verifier(self) -> str:
        return self.default_environment.verifier

    @property
    def requires_rekey(self) -> bool:
        return self.default_environment.requires_rekey


# ------------------------------------------------------------------
# Environment (Week 8 Phase 1) — the new encryption boundary.
#
# A Project is now a container; each Environment owns its own salt,
# verifier, KDF iterations, and ``requires_rekey`` flag. The passphrase
# itself is never stored. A leaked dev environment's passphrase does
# not expose prod's ciphertexts, because the two envs derive their
# keys from independent salts.
# ------------------------------------------------------------------


class Environment(models.Model):
    """A scoped namespace of secrets within a Project, with its own
    passphrase and its own per-env API keys.

    The Week 8 refactor split Project's cryptography into Environment
    so that each environment (dev / staging / prod / ...) is its own
    encryption boundary. Pre-Week 8, a leaked project passphrase
    exposed every secret in the project; post-Week 8, an env's
    passphrase exposes only the secrets in that env.
    """

    project = models.ForeignKey(
        Project, on_delete=models.CASCADE, related_name="environments"
    )
    name = models.CharField(max_length=100)
    # URL-friendly identifier, unique per project. The slug is the URL
    # key (``/projects/<id>/envs/<slug>/...``); the ``name`` is the
    # human label. Slug is constrained to characters that survive URL
    # routing without escaping.
    slug = models.CharField(max_length=64)

    # Cryptography. The passphrase is never stored; ``salt`` and
    # ``verifier`` are enough to derive the same key from a later
    # passphrase entry and to verify the result.
    salt = models.CharField(max_length=64)
    iterations = models.PositiveIntegerField(default=DEFAULT_ITERATIONS)
    verifier = models.TextField()

    # Set by the incident response flow when this environment's
    # passphrase is suspected compromised. The next ``env_unlock``
    # redirects to ``env_rekey`` instead of granting vault access.
    requires_rekey = models.BooleanField(default=False)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        # Slug is the URL key (must be unique within a project); name is
        # the UI label (also unique within a project so the env list
        # never shows two ``"production"`` rows).
        unique_together = (("project", "slug"), ("project", "name"))
        ordering = ("project", "slug")

    def __str__(self):
        return f"{self.project.name}/{self.slug}"

    @staticmethod
    def default_seeded_name() -> str:
        """The human label of the auto-seeded default environment.

        Centralised so Phase 3's env-seeding expansion (development /
        staging / production) can rename the seed consistently without
        grepping for string literals.
        """
        return "Default"

    @staticmethod
    def default_seeded_slug() -> str:
        """The URL slug of the auto-seeded default environment."""
        return "default"


class Secret(models.Model):
    """A key/value pair, e.g. key='gmail.com', value='abc123'. Only the encrypted
    value (ciphertext) is stored."""

    PAYLOAD_STRING = "string"
    PAYLOAD_BINARY = "binary"
    PAYLOAD_TYPE_CHOICES = [
        (PAYLOAD_STRING, "string"),
        (PAYLOAD_BINARY, "binary"),
    ]

    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name="secrets")
    key = models.CharField(max_length=255)
    ciphertext = models.TextField()
    payload_type = models.CharField(
        max_length=16, choices=PAYLOAD_TYPE_CHOICES, default=PAYLOAD_STRING
    )
    idempotency_token = models.CharField(max_length=255, null=True, blank=True)
    tags = models.JSONField(default=list, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    deleted_at = models.DateTimeField(null=True, blank=True)

    RECOVERY_WINDOW = timezone.timedelta(days=30)

    class Meta:
        unique_together = ("project", "key")
        ordering = ("key",)

    def __str__(self):
        return f"{self.project.name}/{self.key}"

    def soft_delete(self):
        if self.deleted_at is None:
            self.deleted_at = timezone.now()
            self.save(update_fields=["deleted_at"])

    def restore(self):
        if self.deleted_at is not None:
            self.deleted_at = None
            self.save(update_fields=["deleted_at"])

    def is_recoverable(self) -> bool:
        if self.deleted_at is None:
            return False
        return timezone.now() <= self.deleted_at + self.RECOVERY_WINDOW


class ProjectAPIKey(models.Model):
    """Authenticates machine access to a project's /api/secrets. Authorizes
    fetching ciphertext only — it does not grant decryption (that needs the
    passphrase, which the server never sees on the API path)."""

    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name="api_keys")
    name = models.CharField(max_length=100, blank=True)
    prefix = models.CharField(max_length=32, unique=True, db_index=True)
    hashed_secret = models.CharField(max_length=64)
    last_four = models.CharField(max_length=4)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    last_used_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"{self.prefix}… ({self.project.name})"

    @classmethod
    def generate(cls, project: Project, name: str = ""):
        public_id = secrets.token_hex(PUBLIC_ID_BYTES)
        secret = secrets.token_urlsafe(SECRET_BYTES)
        prefix = f"{API_KEY_PREFIX}{public_id}"
        full_token = f"{prefix}_{secret}"
        instance = cls.objects.create(
            project=project,
            name=name,
            prefix=prefix,
            hashed_secret=_hash(secret),
            last_four=secret[-4:],
        )
        return instance, full_token

    @staticmethod
    def split_token(token: str):
        if not token.startswith(API_KEY_PREFIX):
            return None, None
        body = token[len(API_KEY_PREFIX):]
        public_id, sep, secret = body.partition("_")
        if not sep or not public_id or not secret:
            return None, None
        return f"{API_KEY_PREFIX}{public_id}", secret

    def is_active(self) -> bool:
        if self.revoked_at is not None:
            return False
        if self.expires_at is not None and self.expires_at <= timezone.now():
            return False
        return True

    def verify(self, secret: str) -> bool:
        return hmac.compare_digest(self.hashed_secret, _hash(secret))

    def revoke(self):
        if self.revoked_at is None:
            self.revoked_at = timezone.now()
            self.save(update_fields=["revoked_at"])


class SecretVersion(models.Model):
    """Version history for a secret. On every secret update, a new version is created.

    Secret.ciphertext always points to the current version for compatibility.
    """

    secret = models.ForeignKey(Secret, on_delete=models.CASCADE, related_name="versions")
    ciphertext = models.TextField()
    label = models.CharField(max_length=255, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ("-created_at",)

    def __str__(self):
        return f"{self.secret.key}/v{self.id}"


class AuditEvent(models.Model):
    """Append-only record of vault access and mutations.

    Rows are write-once: there is no update or delete path. The principal is
    recorded as a free-text label (the API key prefix) because the API
    authenticates a project, not a user. The project FK uses SET_NULL so
    deleting a project does not erase its access history.
    """

    principal = models.CharField(max_length=120, blank=True, default="")
    action = models.CharField(max_length=64)
    organization = models.ForeignKey(
        "organizations.Organization",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="audit_events",
    )
    project = models.ForeignKey(
        Project,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="audit_events",
    )
    secret_key = models.CharField(max_length=255, blank=True, default="")
    timestamp = models.DateTimeField(default=timezone.now, db_index=True)
    source_ip = models.GenericIPAddressField(null=True, blank=True)
    outcome = models.CharField(max_length=32, default="")

    class Meta:
        ordering = ("-timestamp",)

    def __str__(self):
        return f"{self.action}:{self.outcome}"


class WebhookEndpoint(models.Model):
    """Outbound webhook configuration for secret lifecycle events.

    Webhooks are scoped to an organization and receive HMAC-SHA256-signed
    payloads for secret lifecycle events (created, updated, rotated, deleted).
    """

    organization = models.ForeignKey(
        "organizations.Organization",
        on_delete=models.CASCADE,
        related_name="webhook_endpoints",
    )
    url = models.URLField(max_length=2048)
    secret = models.CharField(max_length=255)
    events = models.JSONField(default=list, blank=True)
    active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("id",)

    def __str__(self):
        return f"{self.organization.name}/{self.url}"


class WebhookDelivery(models.Model):
    """Record of a webhook delivery attempt for a lifecycle event.

    Stores the request sent, response received, and delivery status.
    Allows introspection and retry logic for failed deliveries.
    """

    STATUS_PENDING = "pending"
    STATUS_SUCCESS = "success"
    STATUS_FAILED = "failed"
    STATUS_CHOICES = [
        (STATUS_PENDING, "Pending"),
        (STATUS_SUCCESS, "Success"),
        (STATUS_FAILED, "Failed"),
    ]

    endpoint = models.ForeignKey(
        WebhookEndpoint,
        on_delete=models.CASCADE,
        related_name="deliveries",
    )
    event_type = models.CharField(max_length=64)
    payload = models.JSONField()
    status = models.CharField(
        max_length=16, choices=STATUS_CHOICES, default=STATUS_PENDING
    )
    response_status = models.PositiveIntegerField(null=True, blank=True)
    response_body = models.TextField(blank=True, default="")
    error_message = models.TextField(blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    delivered_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ("-created_at",)

    def __str__(self):
        return f"{self.endpoint}/{self.event_type}:{self.status}"
