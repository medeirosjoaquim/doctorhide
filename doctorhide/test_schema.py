"""Tests for the OpenAPI schema and Swagger UI endpoints."""
from django.test import Client, TestCase


class SchemaTests(TestCase):
    """The OpenAPI schema should be served without authentication."""

    def test_schema_returns_200(self):
        client = Client()
        resp = client.get('/api/schema/')
        self.assertEqual(resp.status_code, 200)

    def test_swagger_ui_returns_200(self):
        client = Client()
        resp = client.get('/api/schema/swagger-ui/')
        self.assertEqual(resp.status_code, 200)
