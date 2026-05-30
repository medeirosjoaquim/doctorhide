from django.db import migrations
from django.utils.text import slugify


def _unique_slug(Organization, base):
    base = slugify(base) or "org"
    slug = base
    n = 1
    while Organization.objects.filter(slug=slug).exists():
        n += 1
        slug = f"{base}-{n}"
    return slug


def create_personal_orgs(apps, schema_editor):
    User = apps.get_model("accounts", "User")
    Organization = apps.get_model("organizations", "Organization")
    Membership = apps.get_model("organizations", "Membership")
    Project = apps.get_model("vault", "Project")

    for user in User.objects.all():
        if not Project.objects.filter(
            owner=user, organization__isnull=True
        ).exists():
            continue
        membership = Membership.objects.filter(user=user, role="owner").first()
        if membership is not None:
            org = membership.organization
        else:
            org = Organization.objects.create(
                name=f"{user.get_username()}'s organization",
                slug=_unique_slug(Organization, user.get_username()),
            )
            Membership.objects.create(organization=org, user=user, role="owner")
        Project.objects.filter(owner=user, organization__isnull=True).update(
            organization=org
        )


def noop(apps, schema_editor):
    pass


class Migration(migrations.Migration):

    dependencies = [
        ("vault", "0007_project_organization_nullable"),
        ("organizations", "0002_membership"),
        ("accounts", "0001_initial"),
    ]

    operations = [
        migrations.RunPython(create_personal_orgs, noop),
    ]
