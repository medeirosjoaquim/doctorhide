from django.db import migrations


def seed_versions(apps, schema_editor):
    """Create a v1 SecretVersion for each existing Secret, using its current ciphertext."""
    Secret = apps.get_model("vault", "Secret")
    SecretVersion = apps.get_model("vault", "SecretVersion")

    for secret in Secret.objects.all():
        # Create a version with the current ciphertext, backdated to the secret's creation time.
        SecretVersion.objects.create(
            secret=secret,
            ciphertext=secret.ciphertext,
            label="",
            created_at=secret.created_at,
        )


def noop(apps, schema_editor):
    pass


class Migration(migrations.Migration):

    dependencies = [
        ("vault", "0011_secretversion"),
    ]

    operations = [
        migrations.RunPython(seed_versions, noop),
    ]
