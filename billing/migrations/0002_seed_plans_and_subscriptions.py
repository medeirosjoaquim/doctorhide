from django.db import migrations

FREE_LIMITS = {
    "max_projects": 3,
    "max_secrets": 50,
    "max_seats": 1,
    "max_api_keys": 2,
}

PRO_LIMITS = {
    "max_projects": 50,
    "max_secrets": 5000,
    "max_seats": 25,
    "max_api_keys": 50,
}


def seed(apps, schema_editor):
    Plan = apps.get_model("billing", "Plan")
    Subscription = apps.get_model("billing", "Subscription")
    Organization = apps.get_model("organizations", "Organization")

    free, _ = Plan.objects.get_or_create(
        slug="free",
        defaults={
            "name": "Free",
            "price_cents": 0,
            "interval": "month",
            "limits": FREE_LIMITS,
        },
    )
    Plan.objects.get_or_create(
        slug="pro",
        defaults={
            "name": "Pro",
            "price_cents": 2900,
            "interval": "month",
            "limits": PRO_LIMITS,
        },
    )

    for org in Organization.objects.all():
        Subscription.objects.get_or_create(
            organization=org,
            defaults={"plan": free, "status": "active"},
        )


def unseed(apps, schema_editor):
    Plan = apps.get_model("billing", "Plan")
    Subscription = apps.get_model("billing", "Subscription")
    Subscription.objects.all().delete()
    Plan.objects.filter(slug__in=["free", "pro"]).delete()


class Migration(migrations.Migration):

    dependencies = [
        ("billing", "0001_initial"),
        ("organizations", "0002_membership"),
    ]

    operations = [
        migrations.RunPython(seed, unseed),
    ]
