from django.contrib.auth import views as auth_views
from django.urls import path, reverse_lazy

from . import views

app_name = "accounts"

urlpatterns = [
    path("", views.home, name="home"),
    path("docs", views.docs, name="docs"),
    path("signup", views.signup, name="signup"),
    path("verify-email/<str:token>/", views.verify_email, name="verify_email"),
    path("login", views.login_view, name="login"),
    path("logout", views.logout_view, name="logout"),
    path("totp/enroll", views.totp_enroll, name="totp_enroll"),
    path("totp/verify", views.totp_verify, name="totp_verify"),
    path("totp/backup-codes", views.backup_codes, name="backup_codes"),
    path("totp/backup-codes.pdf", views.download_backup_codes, name="download_backup_codes"),
    path("totp/lost-device", views.lost_mfa_device, name="lost_mfa_device"),
    path("settings", views.settings_view, name="settings"),
    path("delete-account", views.delete_account, name="delete_account"),
    path(
        "password-reset",
        auth_views.PasswordResetView.as_view(
            template_name="accounts/password_reset_form.html",
            email_template_name="accounts/password_reset_email.html",
            subject_template_name="accounts/password_reset_subject.txt",
            success_url=reverse_lazy("accounts:password_reset_done"),
        ),
        name="password_reset",
    ),
    path(
        "password-reset/done",
        auth_views.PasswordResetDoneView.as_view(
            template_name="accounts/password_reset_done.html",
        ),
        name="password_reset_done",
    ),
    path(
        "reset/<uidb64>/<token>",
        auth_views.PasswordResetConfirmView.as_view(
            template_name="accounts/password_reset_confirm.html",
            success_url=reverse_lazy("accounts:password_reset_complete"),
        ),
        name="password_reset_confirm",
    ),
    path(
        "reset/done",
        auth_views.PasswordResetCompleteView.as_view(
            template_name="accounts/password_reset_complete.html",
        ),
        name="password_reset_complete",
    ),
]
