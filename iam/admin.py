from django.contrib import admin, messages

from .models import APIKey, ServiceAccount


@admin.register(ServiceAccount)
class ServiceAccountAdmin(admin.ModelAdmin):
    list_display = ("name", "is_active", "created_by", "created_at")
    list_filter = ("is_active",)
    search_fields = ("name", "description")
    readonly_fields = ("created_by", "created_at", "updated_at")
    actions = ("mint_api_key",)

    def save_model(self, request, obj, form, change):
        if not change and not obj.created_by_id:
            obj.created_by = request.user
        super().save_model(request, obj, form, change)

    @admin.action(description="Mint a new API key")
    def mint_api_key(self, request, queryset):
        for service_account in queryset:
            _, token = APIKey.generate(service_account)
            # The secret is surfaced exactly once here and never stored or shown again.
            self.message_user(
                request,
                f"New API key for '{service_account.name}' — copy it now, it "
                f"will not be shown again: {token}",
                level=messages.WARNING,
            )


@admin.register(APIKey)
class APIKeyAdmin(admin.ModelAdmin):
    list_display = (
        "prefix",
        "service_account",
        "name",
        "last_four",
        "created_at",
        "last_used_at",
        "expires_at",
        "revoked_at",
    )
    list_filter = ("service_account",)
    search_fields = ("prefix", "name")
    readonly_fields = (
        "prefix",
        "hashed_secret",
        "last_four",
        "created_at",
        "last_used_at",
    )
    actions = ("revoke_keys",)

    @admin.action(description="Revoke selected API keys")
    def revoke_keys(self, request, queryset):
        count = 0
        for key in queryset:
            if key.revoked_at is None:
                key.revoke()
                count += 1
        self.message_user(request, f"Revoked {count} key(s).", level=messages.INFO)
