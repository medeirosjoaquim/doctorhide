from django.contrib.auth.models import AbstractUser


class User(AbstractUser):
    """Project user. Thin subclass for now so the model can be customized later
    without a painful AUTH_USER_MODEL swap."""

    pass
