from django.urls import path

from . import api

urlpatterns = [
    path("secrets", api.secrets_list, name="api_secrets_list"),
    path("secrets/<path:key>", api.secret_detail, name="api_secret_detail"),
]
