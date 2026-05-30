from django.core.cache import cache
from django.utils import timezone
from rest_framework import authentication, exceptions

from .models import APIKey

# Throttle last_used_at writes to this interval (in seconds)
LAST_USED_AT_THROTTLE_SECONDS = 3600  # 1 hour


class APIKeyAuthentication(authentication.BaseAuthentication):
    """Authenticate a machine via `Authorization: Bearer dh_live_...`.

    Returns the owning ServiceAccount as request.user and the APIKey as
    request.auth. Returns None (rather than raising) when no Bearer token is
    present, so the request can fall through to SessionAuthentication.
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

        token = parts[1]
        prefix, secret = APIKey.split_token(token)
        if prefix is None:
            raise exceptions.AuthenticationFailed("Invalid API key.")

        try:
            key = APIKey.objects.select_related("service_account").get(prefix=prefix)
        except APIKey.DoesNotExist:
            raise exceptions.AuthenticationFailed("Invalid API key.")

        if not key.verify(secret) or not key.is_active():
            raise exceptions.AuthenticationFailed("Invalid API key.")

        self._update_last_used_at(key)

        return (key.service_account, key)

    def _update_last_used_at(self, key):
        """Update last_used_at only if it hasn't been updated recently."""
        now = timezone.now()
        cache_key = f"apikey_last_used:{key.id}"
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
