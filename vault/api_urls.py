from django.urls import path

from . import api

urlpatterns = [
    path("secrets", api.secrets_list, name="api_secrets_list"),
    path("generate-password", api.generate_password, name="api_generate_password"),
    path("secrets/<path:key>/restore", api.secret_restore, name="api_secret_restore"),
    path("secrets/<path:key>/force", api.secret_force_delete, name="api_secret_force_delete"),
    path("secrets/<path:key>", api.secret_detail, name="api_secret_detail"),
]
