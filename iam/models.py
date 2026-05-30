import hashlib
import hmac
import secrets

from django.conf import settings
from django.db import models
from django.utils import timezone

KEY_PREFIX = "dh_live_"
# Public, non-secret id used to look the key up; the secret half is never stored.
PUBLIC_ID_BYTES = 8
SECRET_BYTES = 32


def _hash_secret(secret: str) -> str:
    """Fast hash is fine: the secret is high-entropy, so brute force is infeasible
    and we never need salting for guessability."""
    return hashlib.sha256(secret.encode()).hexdigest()


class ServiceAccount(models.Model):
    """A machine identity. API keys belong to a service account, not to a person,
    so apps keep working when staff change and each app gets its own scoped identity."""

    name = models.SlugField(max_length=100, unique=True)
    description = models.TextField(blank=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="service_accounts",
    )
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    # Lets DRF treat an authenticated service account as a principal, the same
    # way it treats a logged-in User. request.user may be either type.
    is_authenticated = True
    is_anonymous = False

    def __str__(self):
        return self.name


class APIKey(models.Model):
    """A long-lived bearer credential for a service account. Only a hash of the
    secret is stored; the plaintext is shown exactly once at mint time."""

    service_account = models.ForeignKey(
        ServiceAccount,
        on_delete=models.CASCADE,
        related_name="api_keys",
    )
    name = models.CharField(max_length=100, blank=True)
    prefix = models.CharField(max_length=32, unique=True, db_index=True)
    hashed_secret = models.CharField(max_length=64)
    last_four = models.CharField(max_length=4)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    last_used_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"{self.prefix}… ({self.service_account.name})"

    @classmethod
    def generate(cls, service_account: ServiceAccount, name: str = "", expires_at=None):
        """Create a key and return (instance, full_token). The full token is the
        only time the secret is ever available; it is not persisted."""
        public_id = secrets.token_hex(PUBLIC_ID_BYTES)
        secret = secrets.token_urlsafe(SECRET_BYTES)
        prefix = f"{KEY_PREFIX}{public_id}"
        full_token = f"{prefix}_{secret}"
        instance = cls.objects.create(
            service_account=service_account,
            name=name,
            prefix=prefix,
            hashed_secret=_hash_secret(secret),
            last_four=secret[-4:],
            expires_at=expires_at,
        )
        return instance, full_token

    @staticmethod
    def split_token(token: str):
        """Parse a presented token into (prefix, secret), or (None, None) if malformed."""
        if not token.startswith(KEY_PREFIX):
            return None, None
        body = token[len(KEY_PREFIX):]
        public_id, sep, secret = body.partition("_")
        if not sep or not public_id or not secret:
            return None, None
        return f"{KEY_PREFIX}{public_id}", secret

    def is_active(self) -> bool:
        if self.revoked_at is not None:
            return False
        if self.expires_at is not None and self.expires_at <= timezone.now():
            return False
        return self.service_account.is_active

    def verify(self, secret: str) -> bool:
        return hmac.compare_digest(self.hashed_secret, _hash_secret(secret))

    def revoke(self):
        if self.revoked_at is None:
            self.revoked_at = timezone.now()
            self.save(update_fields=["revoked_at"])
