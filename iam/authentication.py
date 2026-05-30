from django.utils import timezone
from rest_framework import authentication, exceptions

from .models import APIKey


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

        key.last_used_at = timezone.now()
        key.save(update_fields=["last_used_at"])

        return (key.service_account, key)

    def authenticate_header(self, request):
        return self.keyword
