from django.utils import timezone
from rest_framework import authentication, exceptions

from .models import ProjectAPIKey
from . import audit


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

        key.last_used_at = timezone.now()
        key.save(update_fields=["last_used_at"])

        audit.record(
            request, "key.auth", "success", project=key.project, principal=prefix
        )

        return (key.project, key)

    def authenticate_header(self, request):
        return self.keyword
