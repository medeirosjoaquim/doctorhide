"""
Pytest configuration for doctorhide project.

This file is loaded automatically by pytest and configures Django
for test execution when running under pytest instead of manage.py test.
"""

import os
import django
from django.conf import settings

# Configure Django settings if not already configured
if not settings.configured:
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'doctorhide.settings')
    django.setup()
