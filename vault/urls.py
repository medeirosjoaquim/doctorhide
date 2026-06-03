from django.urls import path

from . import views

app_name = "vault"

urlpatterns = [
    path("projects", views.projects, name="projects"),
    path("projects/new", views.project_create, name="create"),
    path("projects/<str:public_id>", views.project_detail, name="detail"),
    path("projects/<str:public_id>/unlock", views.project_unlock, name="unlock"),
    path("projects/<str:public_id>/lock", views.project_lock, name="lock"),
    path("projects/<str:public_id>/rekey", views.project_rekey, name="rekey"),
    path("projects/<str:public_id>/secrets/add", views.secret_add, name="secret_add"),
    path("projects/<str:public_id>/secrets/<int:secret_id>/delete", views.secret_delete, name="secret_delete"),
    path("projects/<str:public_id>/secrets/<int:secret_id>/versions", views.secret_versions, name="secret_versions"),
    path("projects/<str:public_id>/secrets/<int:secret_id>/versions/<int:version_id>/restore", views.secret_version_restore, name="secret_version_restore"),
    path("projects/<str:public_id>/keys/new", views.api_key_create, name="api_key_create"),
    path("projects/<str:public_id>/keys/<int:key_id>/revoke", views.api_key_revoke, name="api_key_revoke"),
]
