from django.core.cache import cache
from django.utils import timezone
from rest_framework import authentication, exceptions

from .models import ProjectAPIKey
from . import audit

# Throttle last_used_at writes to this interval (in seconds)
LAST_USED_AT_THROTTLE_SECONDS = 3600  # 1 hour


class ProjectAPIKeyAuthentication(authentication.BaseAuthentication):
    """Authenticate a machine for a single project via `Authorization: Bearer dhk_...`.

    Returns the project as request.user and the key as request.auth. This
    authorizes reading the project's ciphertext; it does not grant decryption.
    """

    keyword = "Bearer"

    def authenticate(self, request):
        header = authentication.get_authorization_header(request).decode("latin1")
        if not header:
            return None
        parts = header.split()
        if parts[0].lower() != self.keyword.lower():
            return None
        if len(parts) != 2:
            raise exceptions.AuthenticationFailed("Malformed Authorization header.")

        prefix, secret = ProjectAPIKey.split_token(parts[1])
        if prefix is None:
            audit.record(request, "key.auth", "denied")
            raise exceptions.AuthenticationFailed("Invalid API key.")

        try:
            key = ProjectAPIKey.objects.select_related("project").get(prefix=prefix)
        except ProjectAPIKey.DoesNotExist:
            audit.record(request, "key.auth", "denied", principal=prefix)
            raise exceptions.AuthenticationFailed("Invalid API key.")

        if not key.verify(secret) or not key.is_active():
            audit.record(
                request, "key.auth", "denied", project=key.project, principal=prefix
            )
            raise exceptions.AuthenticationFailed("Invalid API key.")

        self._update_last_used_at(key)

        audit.record(
            request, "key.auth", "success", project=key.project, principal=prefix
        )

        return (key.project, key)

    def _update_last_used_at(self, key):
        """Update last_used_at only if it hasn't been updated recently."""
        now = timezone.now()
        cache_key = f"projectapikey_last_used:{key.id}"
        last_update = cache.get(cache_key)

        # If we have a cached timestamp and it's recent, skip the DB write
        if last_update is not None:
            return

        # If last_used_at in DB is recent, cache it and skip the write
        if key.last_used_at is not None:
            age_seconds = (now - key.last_used_at).total_seconds()
            if age_seconds < LAST_USED_AT_THROTTLE_SECONDS:
                cache.set(cache_key, key.last_used_at, LAST_USED_AT_THROTTLE_SECONDS)
                return

        # Otherwise, update the DB and cache the new timestamp
        key.last_used_at = now
        key.save(update_fields=["last_used_at"])
        cache.set(cache_key, now, LAST_USED_AT_THROTTLE_SECONDS)

    def authenticate_header(self, request):
        return self.keyword
