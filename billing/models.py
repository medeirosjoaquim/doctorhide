from django.db import models


class Plan(models.Model):
    """A billable plan with usage limits."""

    class Interval(models.TextChoices):
        MONTH = "month", "Month"
        YEAR = "year", "Year"

    name = models.CharField(max_length=100)
    slug = models.SlugField(unique=True)
    price_cents = models.PositiveIntegerField(default=0)
    interval = models.CharField(
        max_length=10, choices=Interval.choices, default=Interval.MONTH
    )
    limits = models.JSONField(default=dict)

    def __str__(self):
        return self.name


class Subscription(models.Model):
    """Links an organization to the plan it is subscribed to."""

    class Status(models.TextChoices):
        ACTIVE = "active", "Active"
        PAST_DUE = "past_due", "Past due"
        CANCELED = "canceled", "Canceled"

    organization = models.OneToOneField(
        "organizations.Organization",
        on_delete=models.CASCADE,
        related_name="subscription",
    )
    plan = models.ForeignKey(
        Plan, on_delete=models.PROTECT, related_name="subscriptions"
    )
    status = models.CharField(
        max_length=20, choices=Status.choices, default=Status.ACTIVE
    )
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.organization} -> {self.plan}"
