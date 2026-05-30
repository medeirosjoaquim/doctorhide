from django.urls import path

from . import views

app_name = "accounts"

urlpatterns = [
    path("", views.home, name="home"),
    path("docs", views.docs, name="docs"),
    path("signup", views.signup, name="signup"),
    path("login", views.login_view, name="login"),
    path("logout", views.logout_view, name="logout"),
    path("totp/enroll", views.totp_enroll, name="totp_enroll"),
    path("totp/verify", views.totp_verify, name="totp_verify"),
    path("totp/backup-codes", views.backup_codes, name="backup_codes"),
    path("totp/backup-codes.pdf", views.download_backup_codes, name="download_backup_codes"),
]
