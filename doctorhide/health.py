from django.db import connection
from django.http import JsonResponse


def healthz(request):
    """Liveness probe: always 200 if the process can serve requests."""
    return JsonResponse({"status": "ok"})


def readyz(request):
    """Readiness probe: 200 only when the database is reachable, else 503."""
    try:
        connection.ensure_connection()
    except Exception:
        return JsonResponse({"status": "unavailable"}, status=503)
    return JsonResponse({"status": "ok"})
