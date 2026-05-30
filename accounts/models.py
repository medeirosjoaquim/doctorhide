from django.contrib.auth.models import AbstractUser
from django.db import models


class User(AbstractUser):
    """Project user. Thin subclass for now so the model can be customized later
    without a painful AUTH_USER_MODEL swap."""

    email_verified = models.BooleanField(default=False)


class EmailVerificationToken(models.Model):
    """One-time token for email verification on signup."""
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='email_verification_token')
    token = models.CharField(max_length=64, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=['token']),
        ]

    def __str__(self):
        return f"EmailVerificationToken for {self.user.username}"
