"""
URL configuration for doctorhide project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/6.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import include, path
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView

from accounts.views import security_txt
from iam.views import whoami
from vault.incident_views import incident_revoke_all_keys

from .health import healthz, readyz

urlpatterns = [
    # Admin-only incident-response endpoint. Declared before the Django admin
    # catch-all so the path resolves to our DRF view, not 404 inside the
    # admin. The endpoint is itself gated on is_superuser + TOTP + throttle.
    path(
        'admin/incident/revoke-all-keys',
        incident_revoke_all_keys,
        name='incident_revoke_all_keys',
    ),
    path('admin/', admin.site.urls),
    path('.well-known/security.txt', security_txt, name='security_txt'),
    path('', include('accounts.urls')),
    path('', include('organizations.urls')),
    path('', include('vault.urls')),
    path('api/', include('vault.api_urls')),
    path('v1/api/', include('vault.api_urls')),
    path('api/schema/', SpectacularAPIView.as_view(), name='schema'),
    path(
        'api/schema/swagger-ui/',
        SpectacularSwaggerView.as_view(url_name='schema'),
        name='swagger-ui',
    ),
    path('whoami', whoami, name='whoami'),
    path('healthz', healthz, name='healthz'),
    path('readyz', readyz, name='readyz'),
    # Prometheus scrape endpoint. Exposed at /metrics (the convention
    # ``monitoring/prometheus.yml`` is configured to scrape). In
    # production this path should be reachable only from the
    # internal Docker network (no public ingress); the docker-compose
    # wiring already achieves that. If the app is ever exposed
    # directly to the public internet, restrict at the LB layer.
    path('', include('django_prometheus.urls')),
]
