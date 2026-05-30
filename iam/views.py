from rest_framework.decorators import api_view
from rest_framework.response import Response

from .models import ServiceAccount


@api_view(["GET"])
def whoami(request):
    """Probe endpoint reachable by either auth path. Reports the principal so we
    can verify human-session and machine-key auth both resolve correctly."""
    principal = request.user
    if isinstance(principal, ServiceAccount):
        return Response({"type": "service_account", "name": principal.name})
    return Response({"type": "user", "username": principal.get_username()})
