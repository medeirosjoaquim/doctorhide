import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("organizations", "0002_membership"),
        ("vault", "0008_backfill_personal_organizations"),
    ]

    operations = [
        migrations.AlterField(
            model_name="project",
            name="organization",
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.CASCADE,
                related_name="projects",
                to="organizations.organization",
            ),
        ),
    ]
