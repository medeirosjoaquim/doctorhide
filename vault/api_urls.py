from django.urls import path, re_path

from . import api

urlpatterns = [
    path("secrets", api.secrets_list, name="api_secrets_list"),
    path("secrets/batch", api.secrets_batch_get, name="api_secrets_batch_get"),
    path("generate-password", api.generate_password, name="api_generate_password"),
    re_path(
        r"^secrets/(?P<key>.+)/versions/(?P<version_id>\d+)/restore$",
        api.secret_restore_version,
        name="api_secret_restore_version",
    ),
    re_path(
        r"^secrets/(?P<key>.+)/versions$",
        api.secret_list_versions,
        name="api_secret_list_versions",
    ),
    re_path(
        r"^secrets/(?P<key>.+)/describe$",
        api.secret_describe,
        name="api_secret_describe",
    ),
    re_path(
        r"^secrets/(?P<key>.+)/rotate$",
        api.secret_rotate,
        name="api_secret_rotate",
    ),
    re_path(
        r"^secrets/(?P<key>.+)/restore$",
        api.secret_restore,
        name="api_secret_restore",
    ),
    re_path(
        r"^secrets/(?P<key>.+)/force$",
        api.secret_force_delete,
        name="api_secret_force_delete",
    ),
    re_path(r"^secrets/(?P<key>.+)$", api.secret_detail, name="api_secret_detail"),
]
