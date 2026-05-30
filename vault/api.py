from rest_framework.decorators import (
    api_view,
    authentication_classes,
    permission_classes,
)
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from .authentication import ProjectAPIKeyAuthentication


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
    data["keys"] = list(project.secrets.values_list("key", flat=True))
    return Response(data)


@api_view(["GET"])
@authentication_classes([ProjectAPIKeyAuthentication])
@permission_classes([IsAuthenticated])
def secret_detail(request, key):
    """Return the encrypted value for one key. The client derives the key from
    the passphrase + salt and decrypts locally — plaintext never leaves here."""
    project = request.user
    secret = project.secrets.filter(key=key).first()
    if secret is None:
        return Response({"detail": "Not found."}, status=404)
    data = _project_meta(project)
    data["key"] = secret.key
    data["ciphertext"] = secret.ciphertext
    return Response(data)
