import os

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    """Idempotently create a superuser from environment variables.

    Reads DJANGO_SUPERUSER_USERNAME (default "admin"), DJANGO_SUPERUSER_EMAIL
    (default ""), and DJANGO_SUPERUSER_PASSWORD (required). Intended for
    container start-up: it is safe to run on every boot — if the user already
    exists it does nothing. A missing password is a hard error so the container
    refuses to start without one.
    """

    def handle(self, *args, **options):
        username = os.environ.get("DJANGO_SUPERUSER_USERNAME", "admin")
        email = os.environ.get("DJANGO_SUPERUSER_EMAIL", "")
        password = os.environ.get("DJANGO_SUPERUSER_PASSWORD", "")

        if not password:
            raise CommandError(
                "DJANGO_SUPERUSER_PASSWORD is not set. Refusing to create a "
                "superuser without a password."
            )

        User = get_user_model()
        if User.objects.filter(username=username).exists():
            self.stdout.write(f"Superuser '{username}' already exists; nothing to do.")
            return

        User.objects.create_superuser(username=username, email=email, password=password)
        self.stdout.write(self.style.SUCCESS(f"Created superuser '{username}'."))
