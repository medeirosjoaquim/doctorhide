from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.utils.html import format_html

from .models import User
from .views import reset_mfa_admin


class UserAdminCustom(UserAdmin):
    actions = ["reset_mfa_action"]

    def reset_mfa_action(self, request, queryset):
        """Admin action to reset TOTP device and reissue backup codes for selected users.

        Each user gets a fresh TOTP device (old one deleted) and 10 new backup codes.
        Admin should communicate the backup codes to the user securely via support channel.
        """
        for user in queryset:
            codes = reset_mfa_admin(user)
            self.message_user(
                request,
                format_html(
                    "MFA reset for <strong>{}</strong>. Share these codes via secure channel:<br>{}",
                    user.get_username(),
                    "<br>".join(codes),
                ),
            )

    reset_mfa_action.short_description = "Reset MFA device and reissue backup codes"


admin.site.register(User, UserAdminCustom)
