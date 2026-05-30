import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("organizations", "0002_membership"),
        ("vault", "0006_auditevent"),
    ]

    operations = [
        migrations.AddField(
            model_name="project",
            name="organization",
            field=models.ForeignKey(
                null=True,
                on_delete=django.db.models.deletion.CASCADE,
                related_name="projects",
                to="organizations.organization",
            ),
        ),
    ]
