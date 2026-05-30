from django.urls import path, re_path

from . import api

urlpatterns = [
    # Exact match paths must come first to avoid being matched by the catch-all pattern
    path("secrets", api.secrets_list, name="api_secrets_list"),
    path("secrets/batch", api.secrets_batch_get, name="api_secrets_batch_get"),
    path("secrets/export", api.export_secrets, name="api_export_secrets"),
    path("secrets/import", api.import_secrets, name="api_import_secrets"),
    path("generate-password", api.generate_password, name="api_generate_password"),
    # Parameterized paths with version/subaction in the path
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
    # Catch-all pattern - MUST come last
    re_path(r"^secrets/(?P<key>.+)$", api.secret_detail, name="api_secret_detail"),
]
