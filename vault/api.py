import secrets as _secrets
import string

from rest_framework.decorators import (
    api_view,
    authentication_classes,
    permission_classes,
    throttle_classes,
)
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from organizations.permissions import ProjectInOrganization

from .authentication import ProjectAPIKeyAuthentication
from .throttling import ProjectRateThrottle
from .models import Secret
from . import audit

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


DEFAULT_LIMIT = 100
MAX_LIMIT = 1000


def _parse_int(value, default, minimum):
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    if parsed < minimum:
        return default
    return parsed


@api_view(["GET"])
@authentication_classes([ProjectAPIKeyAuthentication])
@permission_classes([IsAuthenticated, ProjectInOrganization])
@throttle_classes([ProjectRateThrottle])
def secrets_list(request):
    """List the keys in the authenticated project. Values are not returned.

    Supports a `prefix` filter (key starts-with), a `tag` filter (key carries
    the tag) and limit/offset pagination.
    """
    project = request.user
    keys = project.secrets.filter(deleted_at__isnull=True)

    prefix = request.query_params.get("prefix")
    if prefix:
        keys = keys.filter(key__startswith=prefix)

    tag = request.query_params.get("tag")
    if tag:
        keys = keys.filter(tags__contains=[tag])

    keys = keys.order_by("key")
    count = keys.count()

    limit = min(
        _parse_int(request.query_params.get("limit"), DEFAULT_LIMIT, minimum=1),
        MAX_LIMIT,
    )
    offset = _parse_int(request.query_params.get("offset"), 0, minimum=0)

    data = _project_meta(project)
    data["count"] = count
    data["limit"] = limit
    data["offset"] = offset
    data["keys"] = list(
        keys.values_list("key", flat=True)[offset : offset + limit]
    )
    audit.record(request, "secret.list", "success", project=project)
    return Response(data)


def _secret_data(project, secret):
    data = _project_meta(project)
    data["key"] = secret.key
    data["ciphertext"] = secret.ciphertext
    data["payload_type"] = secret.payload_type
    return data


@api_view(["GET", "POST"])
@authentication_classes([ProjectAPIKeyAuthentication])
@permission_classes([IsAuthenticated, ProjectInOrganization])
@throttle_classes([ProjectRateThrottle])
def secrets_batch_get(request):
    """Return ciphertext + metadata for several keys in one request. Keys come
    from a JSON list body (POST {"keys": [...]}) or repeated ?key= query params
    (GET). Like the single-secret read, plaintext never leaves here — only the
    client-encrypted ciphertext is returned. Missing or soft-deleted keys are
    reported separately rather than failing the whole request."""
    project = request.user
    if request.method == "POST":
        keys = request.data.get("keys")
    else:
        keys = request.query_params.getlist("key")
    if not isinstance(keys, (list, tuple)) or not keys:
        return Response(
            {"detail": "keys is required and must be a non-empty list."}, status=400
        )

    found = {
        s.key: s
        for s in project.secrets.filter(key__in=keys, deleted_at__isnull=True)
    }
    data = _project_meta(project)
    data["secrets"] = [
        {
            "key": k,
            "ciphertext": found[k].ciphertext,
            "payload_type": found[k].payload_type,
        }
        for k in keys
        if k in found
    ]
    data["missing"] = [k for k in keys if k not in found]
    return Response(data)


def _write_secret(request, key, require_new):
    """Create (POST) or upsert (PUT) a secret from client-supplied ciphertext.

    Zero-knowledge: only ciphertext is accepted — a plaintext field is rejected.
    An optional ClientRequestToken makes retries idempotent: replaying the same
    token for the same key returns the stored secret without re-applying."""
    project = request.user
    if "plaintext" in request.data:
        return Response(
            {"detail": "Plaintext is not accepted; send client-encrypted ciphertext."},
            status=400,
        )
    ciphertext = request.data.get("ciphertext")
    if not ciphertext:
        return Response({"detail": "ciphertext is required."}, status=400)
    payload_type = request.data.get("payload_type", Secret.PAYLOAD_STRING)
    valid_payload_types = {c[0] for c in Secret.PAYLOAD_TYPE_CHOICES}
    if payload_type not in valid_payload_types:
        return Response(
            {"detail": "payload_type must be one of: "
                       + ", ".join(sorted(valid_payload_types)) + "."},
            status=400,
        )
    token = request.data.get("ClientRequestToken") or None
    tags = request.data.get("tags")
    if tags is not None and (
        not isinstance(tags, list) or not all(isinstance(t, str) for t in tags)
    ):
        return Response(
            {"detail": "tags must be a list of strings."}, status=400
        )

    secret = project.secrets.filter(key=key).first()
    if secret is not None and token and secret.idempotency_token == token:
        # Idempotent replay: do nothing, return the existing secret.
        return Response(_secret_data(project, secret), status=200)
    if require_new and secret is not None:
        return Response(
            {"detail": "Secret already exists; use PUT to update."}, status=409
        )

    created = secret is None
    if created:
        secret = Secret(project=project, key=key)
    secret.ciphertext = ciphertext
    secret.payload_type = payload_type
    secret.idempotency_token = token
    if tags is not None:
        secret.tags = tags
    secret.deleted_at = None
    secret.save()
    audit.record(
        request,
        "secret.create" if created else "secret.update",
        "success",
        project=project,
        secret_key=key,
    )
    return Response(_secret_data(project, secret), status=201 if created else 200)


@api_view(["GET", "POST", "PUT", "DELETE"])
@authentication_classes([ProjectAPIKeyAuthentication])
@permission_classes([IsAuthenticated, ProjectInOrganization])
@throttle_classes([ProjectRateThrottle])
def secret_detail(request, key):
    """GET returns the encrypted value for one key; the client derives the key
    from the passphrase + salt and decrypts locally — plaintext never leaves
    here. POST creates and PUT upserts the encrypted value. DELETE soft-deletes
    the secret, keeping it recoverable for a window."""
    project = request.user
    if request.method == "POST":
        return _write_secret(request, key, require_new=True)
    if request.method == "PUT":
        return _write_secret(request, key, require_new=False)
    secret = project.secrets.filter(key=key, deleted_at__isnull=True).first()
    if secret is None:
        action = "secret.delete" if request.method == "DELETE" else "secret.read"
        audit.record(request, action, "denied", project=project, secret_key=key)
        return Response({"detail": "Not found."}, status=404)
    if request.method == "DELETE":
        secret.soft_delete()
        audit.record(request, "secret.delete", "success", project=project, secret_key=key)
        return Response(status=204)
    audit.record(request, "secret.read", "success", project=project, secret_key=key)
    return Response(_secret_data(project, secret))


@api_view(["GET"])
@authentication_classes([ProjectAPIKeyAuthentication])
@permission_classes([IsAuthenticated, ProjectInOrganization])
@throttle_classes([ProjectRateThrottle])
def secret_describe(request, key):
    """Return a secret's metadata (key, timestamps) without the ciphertext.
    Lets clients inspect existence and audit fields without fetching the
    encrypted value. Includes soft-deleted secrets so deleted_at is visible."""
    project = request.user
    secret = project.secrets.filter(key=key).first()
    if secret is None:
        return Response({"detail": "Not found."}, status=404)
    return Response(
        {
            "key": secret.key,
            "payload_type": secret.payload_type,
            "created_at": secret.created_at,
            "updated_at": secret.updated_at,
            "deleted_at": secret.deleted_at,
        }
    )


@api_view(["POST"])
@authentication_classes([ProjectAPIKeyAuthentication])
@permission_classes([IsAuthenticated, ProjectInOrganization])
@throttle_classes([ProjectRateThrottle])
def secret_restore(request, key):
    """Restore a soft-deleted secret by clearing deleted_at. Scoped to the
    authenticated project; only secrets currently soft-deleted are restorable."""
    project = request.user
    secret = project.secrets.filter(key=key, deleted_at__isnull=False).first()
    if secret is None:
        audit.record(request, "secret.restore", "denied", project=project, secret_key=key)
        return Response({"detail": "Not found."}, status=404)
    secret.restore()
    audit.record(request, "secret.restore", "success", project=project, secret_key=key)
    data = _project_meta(project)
    data["key"] = secret.key
    return Response(data)


@api_view(["DELETE"])
@authentication_classes([ProjectAPIKeyAuthentication])
@permission_classes([IsAuthenticated, ProjectInOrganization])
@throttle_classes([ProjectRateThrottle])
def secret_force_delete(request, key):
    """Hard-delete a secret, removing the row entirely (no recovery). Scoped to
    the authenticated project; works on active or soft-deleted secrets."""
    project = request.user
    secret = project.secrets.filter(key=key).first()
    if secret is None:
        audit.record(request, "secret.force_delete", "denied", project=project, secret_key=key)
        return Response({"detail": "Not found."}, status=404)
    secret.delete()
    audit.record(request, "secret.force_delete", "success", project=project, secret_key=key)
    return Response(status=204)


@api_view(["GET"])
@authentication_classes([ProjectAPIKeyAuthentication])
@permission_classes([IsAuthenticated, ProjectInOrganization])
@throttle_classes([ProjectRateThrottle])
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
