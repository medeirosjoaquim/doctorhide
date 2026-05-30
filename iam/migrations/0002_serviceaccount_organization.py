import django.db.models.deletion
from django.db import migrations, models
from django.utils.text import slugify


def _unique_slug(Organization, base):
    base = slugify(base) or "org"
    slug = base
    n = 1
    while Organization.objects.filter(slug=slug).exists():
        n += 1
        slug = f"{base}-{n}"
    return slug


def backfill_organizations(apps, schema_editor):
    Organization = apps.get_model("organizations", "Organization")
    Membership = apps.get_model("organizations", "Membership")
    ServiceAccount = apps.get_model("iam", "ServiceAccount")

    def personal_org(user):
        membership = Membership.objects.filter(user=user, role="owner").first()
        if membership is not None:
            return membership.organization
        org = Organization.objects.create(
            name=f"{user.get_username()}'s organization",
            slug=_unique_slug(Organization, user.get_username()),
        )
        Membership.objects.create(organization=org, user=user, role="owner")
        return org

    for account in ServiceAccount.objects.filter(organization__isnull=True):
        if account.created_by_id:
            account.organization = personal_org(account.created_by)
            account.save(update_fields=["organization"])


def noop(apps, schema_editor):
    pass


class Migration(migrations.Migration):

    dependencies = [
        ('iam', '0001_initial'),
        ('organizations', '0002_membership'),
    ]

    operations = [
        migrations.AddField(
            model_name='serviceaccount',
            name='organization',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='service_accounts', to='organizations.organization'),
        ),
        migrations.RunPython(backfill_organizations, noop),
    ]
