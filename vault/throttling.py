from rest_framework.settings import api_settings
from rest_framework.throttling import SimpleRateThrottle


class ProjectRateThrottle(SimpleRateThrottle):
    """Rate-limit the dhk_ vault API per authenticated project. The rate comes
    from the ``vault_api`` scope in ``DEFAULT_THROTTLE_RATES`` (env-configurable).
    Requests are bucketed by the project's primary key so each project gets its
    own quota; unauthenticated requests fall back to the client IP."""

    scope = "vault_api"

    def get_rate(self):
        # Read the rate live from DRF settings rather than the THROTTLE_RATES
        # dict captured on the base class at import time, so the configured
        # rate tracks env config and test overrides.
        return api_settings.DEFAULT_THROTTLE_RATES.get(self.scope)

    def get_cache_key(self, request, view):
        project = request.user
        ident = getattr(project, "pk", None)
        if ident is None:
            ident = self.get_ident(request)
        return self.cache_format % {"scope": self.scope, "ident": ident}
