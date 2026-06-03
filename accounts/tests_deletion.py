from django.contrib.auth import get_user_model
from django.test import Client, TestCase
from django.urls import reverse
from django_otp.oath import totp
from django_otp.plugins.otp_static.models import StaticDevice, StaticToken
from django_otp.plugins.otp_totp.models import TOTPDevice

from iam.models import ServiceAccount
from organizations.models import Membership, Organization

User = get_user_model()

PASSWORD = "sup3rSecret!pw"
PENDING_KEY = "totp_pending_user_id"


def current_totp(device):
    code = totp(device.bin_key, step=device.step, t0=device.t0, digits=device.digits)
    return str(code).zfill(device.digits)


def confirmed_totp(user):
    return TOTPDevice.objects.create(user=user, name="default", confirmed=True)


def create_backup_code(user):
    """Create a backup code device and return one token."""
    device = StaticDevice.objects.create(user=user, name="backup", confirmed=True)
    token = StaticToken.random_token()
    device.token_set.create(token=token)
    return token


def set_pending(client, user):
    session = client.session
    session[PENDING_KEY] = user.pk
    session.save()


def login_user(client, user, device):
    """Fully log in a user with OTP."""
    set_pending(client, user)
    resp = client.post(reverse("accounts:totp_verify"), {"token": current_totp(device)})
    assert resp.status_code == 302
    assert resp.url == reverse("vault:projects")


class AccountDeletionTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(username="alice", password=PASSWORD)
        self.device = confirmed_totp(self.user)

    def test_redirect_to_login_if_not_authenticated(self):
        resp = self.client.get(reverse("accounts:delete_account"))
        self.assertEqual(resp.status_code, 302)
        self.assertIn(reverse("accounts:login"), resp.url)

    def test_redirect_to_login_if_otp_not_verified(self):
        # User is authenticated but not verified (TOTP not passed).
        set_pending(self.client, self.user)
        resp = self.client.get(reverse("accounts:delete_account"))
        self.assertEqual(resp.status_code, 302)

    def test_get_shows_delete_form(self):
        login_user(self.client, self.user, self.device)
        resp = self.client.get(reverse("accounts:delete_account"))
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "Delete your account")
        self.assertContains(resp, "Two-factor code")

    def test_wrong_otp_code_shows_error(self):
        login_user(self.client, self.user, self.device)
        resp = self.client.post(
            reverse("accounts:delete_account"),
            {"token": "000000"},
        )
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "Invalid code.")
        self.assertTrue(User.objects.filter(username="alice").exists())

    def test_blocks_deletion_if_no_otp_code_provided(self):
        login_user(self.client, self.user, self.device)
        resp = self.client.post(
            reverse("accounts:delete_account"),
            {"token": ""},
        )
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "Invalid code.")
        self.assertTrue(User.objects.filter(username="alice").exists())

    def test_happy_path_deletes_user_and_logs_out(self):
        login_user(self.client, self.user, self.device)
        # Use a backup code for deletion (avoids TOTP timing issues)
        backup_code = create_backup_code(self.user)
        resp = self.client.post(
            reverse("accounts:delete_account"),
            {"token": backup_code},
        )
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "Account deleted")
        self.assertFalse(User.objects.filter(username="alice").exists())
        # Verify user is logged out.
        resp = self.client.get(reverse("vault:projects"))
        self.assertEqual(resp.status_code, 302)

    def test_blocks_deletion_if_last_owner_with_other_members(self):
        """User is the sole owner of an org with other members."""
        login_user(self.client, self.user, self.device)

        # Create org with alice as owner.
        org = Organization.objects.create(name="Test Org", slug="test-org")
        Membership.objects.create(
            organization=org, user=self.user, role=Membership.ROLE_OWNER
        )
        # Add another member.
        bob = User.objects.create_user(username="bob", password=PASSWORD)
        Membership.objects.create(
            organization=org, user=bob, role=Membership.ROLE_MEMBER
        )

        backup_code = create_backup_code(self.user)
        resp = self.client.post(
            reverse("accounts:delete_account"),
            {"token": backup_code},
        )
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "You are the last owner")
        self.assertTrue(User.objects.filter(username="alice").exists())

    def test_allows_deletion_if_owner_but_no_other_members(self):
        """User is sole owner, but org has no other members (can delete)."""
        login_user(self.client, self.user, self.device)

        # Create org with alice as owner, no other members.
        org = Organization.objects.create(name="Solo Org", slug="solo-org")
        Membership.objects.create(
            organization=org, user=self.user, role=Membership.ROLE_OWNER
        )

        backup_code = create_backup_code(self.user)
        resp = self.client.post(
            reverse("accounts:delete_account"),
            {"token": backup_code},
        )
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "Account deleted")
        self.assertFalse(User.objects.filter(username="alice").exists())

    def test_allows_deletion_if_not_owner(self):
        """User is not an owner, so no org ownership constraints."""
        login_user(self.client, self.user, self.device)

        # Create org with alice as member (not owner).
        org = Organization.objects.create(name="Shared Org", slug="shared-org")
        Membership.objects.create(
            organization=org, user=self.user, role=Membership.ROLE_MEMBER
        )

        backup_code = create_backup_code(self.user)
        resp = self.client.post(
            reverse("accounts:delete_account"),
            {"token": backup_code},
        )
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "Account deleted")
        self.assertFalse(User.objects.filter(username="alice").exists())

    def test_blocks_deletion_if_created_service_accounts(self):
        """User created service accounts; must be deleted/reassigned first."""
        login_user(self.client, self.user, self.device)

        # Create a service account owned by alice.
        org = Organization.objects.create(name="Service Org", slug="service-org")
        Membership.objects.create(
            organization=org, user=self.user, role=Membership.ROLE_OWNER
        )
        ServiceAccount.objects.create(
            name="test-sa",
            created_by=self.user,
            organization=org,
        )

        backup_code = create_backup_code(self.user)
        resp = self.client.post(
            reverse("accounts:delete_account"),
            {"token": backup_code},
        )
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "service accounts")
        self.assertTrue(User.objects.filter(username="alice").exists())

    def test_allows_deletion_if_no_service_accounts(self):
        """User did not create any service accounts."""
        login_user(self.client, self.user, self.device)

        backup_code = create_backup_code(self.user)
        resp = self.client.post(
            reverse("accounts:delete_account"),
            {"token": backup_code},
        )
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "Account deleted")
        self.assertFalse(User.objects.filter(username="alice").exists())

    def test_cascades_on_delete_user_projects(self):
        """User's projects cascade delete with user."""
        from vault.models import Project

        login_user(self.client, self.user, self.device)

        # Create a project owned by alice.
        org = Organization.objects.create(name="Project Org", slug="proj-org")
        Membership.objects.create(
            organization=org, user=self.user, role=Membership.ROLE_OWNER
        )
        project = Project.objects.create(
            owner=self.user,
            organization=org,
            public_id=Project.new_public_id(),
            name="test-project",
        )
        # Project no longer owns salt/verifier (Week 8 Phase 1); the
        # signal-seeded default env starts with random crypto, which is
        # fine for this test (it only checks cascade-delete behaviour,
        # not crypto validity).
        _ = project.default_environment
        project_id = Project.objects.first().id

        backup_code = create_backup_code(self.user)
        resp = self.client.post(
            reverse("accounts:delete_account"),
            {"token": backup_code},
        )
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(Project.objects.filter(id=project_id).exists())

    def test_deletes_otp_devices_with_user(self):
        """User's OTP devices are deleted when user is deleted."""
        login_user(self.client, self.user, self.device)

        device_id = self.device.id
        backup_code = create_backup_code(self.user)
        resp = self.client.post(
            reverse("accounts:delete_account"),
            {"token": backup_code},
        )
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(TOTPDevice.objects.filter(id=device_id).exists())

    def test_deletes_memberships_with_user(self):
        """User's organization memberships are deleted when user is deleted."""
        login_user(self.client, self.user, self.device)

        # Create membership.
        org = Organization.objects.create(name="Delete Org", slug="delete-org")
        membership = Membership.objects.create(
            organization=org, user=self.user, role=Membership.ROLE_MEMBER
        )
        membership_id = membership.id

        backup_code = create_backup_code(self.user)
        resp = self.client.post(
            reverse("accounts:delete_account"),
            {"token": backup_code},
        )
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(Membership.objects.filter(id=membership_id).exists())

    def test_allows_deletion_if_multiple_owners_in_org(self):
        """User is owner but org has other owners; can delete."""
        login_user(self.client, self.user, self.device)

        org = Organization.objects.create(name="Multi Owner Org", slug="multi-owner")
        Membership.objects.create(
            organization=org, user=self.user, role=Membership.ROLE_OWNER
        )
        carol = User.objects.create_user(username="carol", password=PASSWORD)
        Membership.objects.create(
            organization=org, user=carol, role=Membership.ROLE_OWNER
        )

        backup_code = create_backup_code(self.user)
        resp = self.client.post(
            reverse("accounts:delete_account"),
            {"token": backup_code},
        )
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "Account deleted")
        self.assertFalse(User.objects.filter(username="alice").exists())

    def test_uses_backup_code_for_deletion(self):
        """User can also use a backup code to delete account."""
        login_user(self.client, self.user, self.device)

        # Create backup code and use it for deletion.
        backup_code = create_backup_code(self.user)
        resp = self.client.post(
            reverse("accounts:delete_account"),
            {"token": backup_code},
        )
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "Account deleted")
        self.assertFalse(User.objects.filter(username="alice").exists())
