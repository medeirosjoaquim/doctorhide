import django.db.models.deletion
from django.db import migrations, models


def backfill_organizations(apps, schema_editor):
    AuditEvent = apps.get_model("vault", "AuditEvent")

    # An audit event belongs to the organization of the project it touched.
    # Events without a project (e.g. account-level actions) have no
    # organization to infer and stay null.
    for event in AuditEvent.objects.filter(
        organization__isnull=True, project__isnull=False
    ):
        org_id = event.project.organization_id
        if org_id is not None:
            event.organization_id = org_id
            event.save(update_fields=["organization"])


def noop(apps, schema_editor):
    pass


class Migration(migrations.Migration):

    dependencies = [
        ('organizations', '0002_membership'),
        ('vault', '0009_project_organization_required'),
    ]

    operations = [
        migrations.AddField(
            model_name='auditevent',
            name='organization',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='audit_events', to='organizations.organization'),
        ),
        migrations.RunPython(backfill_organizations, noop),
    ]
