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
    public_id = models.CharField(max_length=24, unique=True, db_index=True)
    name = models.CharField(max_length=100)
    salt = models.CharField(max_length=64)
    iterations = models.PositiveIntegerField(default=DEFAULT_ITERATIONS)
    verifier = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    # Lets DRF treat an authenticated project (via API key) as a principal.
    is_authenticated = True
    is_anonymous = False

    class Meta:
        unique_together = ("owner", "name")

    def __str__(self):
        return self.name

    @staticmethod
    def new_public_id() -> str:
        return "proj_" + secrets.token_hex(PUBLIC_ID_BYTES)


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


class AuditEvent(models.Model):
    """Append-only record of vault access and mutations.

    Rows are write-once: there is no update or delete path. The principal is
    recorded as a free-text label (the API key prefix) because the API
    authenticates a project, not a user. The project FK uses SET_NULL so
    deleting a project does not erase its access history.
    """

    principal = models.CharField(max_length=120, blank=True, default="")
    action = models.CharField(max_length=64)
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
