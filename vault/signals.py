from django.db.models.signals import post_save, pre_delete
from django.dispatch import receiver

from .models import Secret
from .webhooks import emit_webhook


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
