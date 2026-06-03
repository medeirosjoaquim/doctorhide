import secrets

from django.db.models.signals import post_save, pre_delete
from django.dispatch import receiver

from . import crypto
from .models import Environment, Project, Secret
from .webhooks import emit_webhook


@receiver(post_save, sender=Project)
def on_project_created(sender, instance, created, **kwargs):
    """Auto-seed a ``default`` Environment for every new Project.

    Week 8 Phase 1: a Project is now a container; the cryptography
    (salt, verifier, iterations) lives on Environment, not Project.
    The seeded env starts with crypto derived from a freshly-generated
    random passphrase — i.e. the env is "valid" in shape (it has the
    required fields populated) but its data is not recoverable. Phase
    3 rewires ``project_create`` to seed three envs (development,
    staging, production) with the user's chosen passphrase, replacing
    this transient default.

    The signal is ``created``-guarded so re-saving a Project does not
    clobber a real env's crypto. Direct ORM ``Project()`` + ``.save()``
    still triggers the seed, which is the desired behaviour for tests
    and for the rare case where a Project is created via the shell.
    """
    if not created:
        return
    if Environment.objects.filter(
        project=instance, slug=Environment.default_seeded_slug()
    ).exists():
        return
    salt = crypto.generate_salt()
    # Random key; the data is unrecoverable, the env is "valid" in
    # shape so the test factory and views can write/read crypto fields
    # without special-casing the empty case. Phase 3's project_create
    # overwrites this on first user interaction.
    random_key = crypto.derive_key(secrets.token_urlsafe(32), salt)
    Environment.objects.create(
        project=instance,
        name=Environment.default_seeded_name(),
        slug=Environment.default_seeded_slug(),
        salt=salt,
        iterations=crypto.DEFAULT_ITERATIONS,
        verifier=crypto.make_verifier(random_key),
    )


@receiver(post_save, sender=Secret)
def on_secret_created_or_updated(sender, instance, created, **kwargs):
    """Emit webhook on secret creation or update."""
    if created:
        event_type = "secret.created"
    else:
        event_type = "secret.updated"

    payload = {
        "event": event_type,
        "key": instance.key,
        "project_id": instance.project.public_id,
        "payload_type": instance.payload_type,
        "created_at": instance.created_at.isoformat(),
        "updated_at": instance.updated_at.isoformat(),
    }
    emit_webhook(instance.project.organization_id, event_type, payload)


@receiver(pre_delete, sender=Secret)
def on_secret_deleted(sender, instance, **kwargs):
    """Emit webhook on secret hard deletion."""
    event_type = "secret.deleted"
    payload = {
        "event": event_type,
        "key": instance.key,
        "project_id": instance.project.public_id,
        "created_at": instance.created_at.isoformat(),
        "deleted_at": instance.updated_at.isoformat(),
    }
    emit_webhook(instance.project.organization_id, event_type, payload)
