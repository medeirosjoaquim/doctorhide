import secrets as _secrets
import string

from rest_framework.decorators import (
    api_view,
    authentication_classes,
    permission_classes,
)
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from .authentication import ProjectAPIKeyAuthentication

CHARSET_TYPES = {
    "lower": string.ascii_lowercase,
    "upper": string.ascii_uppercase,
    "digits": string.digits,
    "symbols": "!@#$%^&*()-_=+[]{};:,.<>?",
}


def _project_meta(project):
    """Everything a client needs to derive the decryption key — but not the
    passphrase, which the server never has."""
    return {
        "project_id": project.public_id,
        "kdf": "pbkdf2-sha256",
        "salt": project.salt,
        "iterations": project.iterations,
    }


@api_view(["GET"])
@authentication_classes([ProjectAPIKeyAuthentication])
@permission_classes([IsAuthenticated])
def secrets_list(request):
    """List the keys in the authenticated project. Values are not returned."""
    project = request.user
    data = _project_meta(project)
    data["keys"] = list(
        project.secrets.filter(deleted_at__isnull=True).values_list("key", flat=True)
    )
    return Response(data)


@api_view(["GET", "DELETE"])
@authentication_classes([ProjectAPIKeyAuthentication])
@permission_classes([IsAuthenticated])
def secret_detail(request, key):
    """GET returns the encrypted value for one key; the client derives the key
    from the passphrase + salt and decrypts locally — plaintext never leaves
    here. DELETE soft-deletes the secret, keeping it recoverable for a window."""
    project = request.user
    secret = project.secrets.filter(key=key, deleted_at__isnull=True).first()
    if secret is None:
        return Response({"detail": "Not found."}, status=404)
    if request.method == "DELETE":
        secret.soft_delete()
        return Response(status=204)
    data = _project_meta(project)
    data["key"] = secret.key
    data["ciphertext"] = secret.ciphertext
    return Response(data)


@api_view(["GET"])
@authentication_classes([ProjectAPIKeyAuthentication])
@permission_classes([IsAuthenticated])
def generate_password(request):
    """Generate a random value using the stdlib `secrets` module. The result is
    returned but never persisted — this is a stateless helper for clients."""
    try:
        length = int(request.query_params.get("length", 24))
    except (TypeError, ValueError):
        return Response({"detail": "length must be an integer."}, status=400)
    if length < 8 or length > 256:
        return Response({"detail": "length must be between 8 and 256."}, status=400)

    require_param = request.query_params.get("require-types")
    if require_param:
        requested = [t.strip() for t in require_param.split(",") if t.strip()]
        unknown = [t for t in requested if t not in CHARSET_TYPES]
        if unknown:
            return Response(
                {"detail": "Unknown require-types: " + ", ".join(unknown)},
                status=400,
            )
    else:
        requested = list(CHARSET_TYPES)

    exclude = set(request.query_params.get("exclude", ""))
    type_pools = {}
    for t in requested:
        pool = [c for c in CHARSET_TYPES[t] if c not in exclude]
        if not pool:
            return Response(
                {"detail": f"No characters left for type '{t}' after exclude."},
                status=400,
            )
        type_pools[t] = pool

    if length < len(type_pools):
        return Response(
            {"detail": "length too small to satisfy required types."}, status=400
        )

    full_pool = [c for pool in type_pools.values() for c in pool]
    chars = [_secrets.choice(pool) for pool in type_pools.values()]
    chars += [_secrets.choice(full_pool) for _ in range(length - len(chars))]
    _secrets.SystemRandom().shuffle(chars)

    return Response({"value": "".join(chars), "length": length})
