from django.apps import AppConfig


class VaultConfig(AppConfig):
    name = 'vault'

    def ready(self):
        from . import signals  # noqa: F401
