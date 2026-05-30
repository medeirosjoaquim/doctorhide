import base64
import io
import secrets

import qrcode
from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth import login as auth_login
from django.contrib.auth import logout as auth_logout
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.core.mail import send_mail
from django.http import HttpResponse
from django.shortcuts import redirect, render
from django.utils import timezone
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas
from django_otp import login as otp_login
from django_otp import match_token
from django_otp.decorators import otp_required
from django_otp.plugins.otp_static.models import StaticDevice, StaticToken
from django_otp.plugins.otp_totp.models import TOTPDevice

from .models import EmailVerificationToken

User = get_user_model()

PENDING_SESSION_KEY = "totp_pending_user_id"
BACKUP_CODES_SESSION_KEY = "totp_backup_codes"
BACKUP_CODE_COUNT = 10


def _pending_user(request):
    """The user who passed the password step but has not yet cleared TOTP."""
    user_id = request.session.get(PENDING_SESSION_KEY)
    if not user_id:
        return None
    return User.objects.filter(pk=user_id).first()


def _confirmed_totp(user):
    return TOTPDevice.objects.filter(user=user, confirmed=True).first()


def home(request):
    return render(request, "accounts/home.html")


def docs(request):
    return render(request, "accounts/docs.html")


def terms(request):
    return render(request, "accounts/terms.html")


def privacy(request):
    return render(request, "accounts/privacy.html")


def security(request):
    return render(request, "accounts/security.html")


def security_txt(request):
    content = """Contact: security@doctorhide.com
Expires: 2025-12-31T00:00:00Z
"""
    return HttpResponse(content, content_type="text/plain")


def signup(request):
    if request.user.is_authenticated and request.user.is_verified():
        return redirect("vault:projects")

    errors = []
    username = ""
    email = ""
    if request.method == "POST":
        username = request.POST.get("username", "").strip()
        email = request.POST.get("email", "").strip()
        password1 = request.POST.get("password1", "")
        password2 = request.POST.get("password2", "")
        accept_terms = request.POST.get("accept_terms", "").strip()

        if not username:
            errors.append("Username is required.")
        elif User.objects.filter(username__iexact=username).exists():
            errors.append("That username is already taken.")
        if not email:
            errors.append("Email is required.")
        elif User.objects.filter(email__iexact=email).exists():
            errors.append("That email is already in use.")
        if password1 != password2:
            errors.append("Passwords don't match.")
        if not accept_terms:
            errors.append("You must accept the Terms of Service and Privacy Policy.")

        if not errors:
            try:
                validate_password(password1)
            except ValidationError as exc:
                errors.extend(exc.messages)

        if not errors:
            user = User.objects.create_user(username=username, email=email, password=password1)
            # Record terms acceptance
            user.accepted_terms_version = "1.0"
            user.accepted_at = timezone.now()
            user.save()
            # Generate email verification token
            token = secrets.token_urlsafe(48)
            EmailVerificationToken.objects.update_or_create(
                user=user,
                defaults={'token': token}
            )
            # Send verification email
            verification_url = request.build_absolute_uri(f"/accounts/verify-email/{token}/")
            send_mail(
                subject="Verify your doctorhide email",
                message=f"Click the link to verify your email:\n\n{verification_url}",
                from_email="noreply@doctorhide.com",
                recipient_list=[email],
            )
            # New humans must enrol TOTP before the account is usable.
            request.session[PENDING_SESSION_KEY] = user.pk
            return redirect("accounts:totp_enroll")

    return render(request, "accounts/signup.html", {"errors": errors, "username": username, "email": email})


def login_view(request):
    if request.user.is_authenticated and request.user.is_verified():
        return redirect("vault:projects")

    error = None
    if request.method == "POST":
        user = authenticate(
            request,
            username=request.POST.get("username"),
            password=request.POST.get("password"),
        )
        if user is None or not user.is_active:
            error = "Invalid username or password."
        else:
            # Password verified, but not logged in yet — TOTP is required next.
            request.session[PENDING_SESSION_KEY] = user.pk
            if _confirmed_totp(user):
                return redirect("accounts:totp_verify")
            return redirect("accounts:totp_enroll")

    return render(request, "accounts/login.html", {"error": error})


def totp_enroll(request):
    user = _pending_user(request)
    if user is None:
        return redirect("accounts:login")
    if _confirmed_totp(user):
        # Already enrolled — go straight to the challenge.
        return redirect("accounts:totp_verify")

    device, _ = TOTPDevice.objects.get_or_create(
        user=user, confirmed=False, defaults={"name": "default"}
    )

    error = None
    if request.method == "POST":
        token = request.POST.get("token", "").strip()
        if device.verify_token(token):
            device.confirmed = True
            device.save()
            codes = _issue_backup_codes(user)
            _complete_login(request, user, device)
            request.session[BACKUP_CODES_SESSION_KEY] = codes
            return redirect("accounts:backup_codes")
        error = "That code didn't match. Make sure your device clock is correct and try again."

    img = qrcode.make(device.config_url)
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    qr_data_uri = "data:image/png;base64," + base64.b64encode(buffer.getvalue()).decode()

    return render(
        request,
        "accounts/totp_enroll.html",
        {"qr_data_uri": qr_data_uri, "secret": device.config_url, "error": error},
    )


def totp_verify(request):
    user = _pending_user(request)
    if user is None:
        return redirect("accounts:login")
    if not _confirmed_totp(user):
        return redirect("accounts:totp_enroll")

    error = None
    if request.method == "POST":
        token = request.POST.get("token", "").strip()
        # match_token checks every confirmed device (TOTP + backup codes),
        # enforces drift tolerance, and records last_t to block replay.
        device = match_token(user, token)
        if device is not None:
            _complete_login(request, user, device)
            return redirect("vault:projects")
        error = "Invalid code."

    return render(request, "accounts/totp_verify.html", {"error": error})


def backup_codes(request):
    if not request.user.is_authenticated:
        return redirect("accounts:login")
    # Kept in the session (not popped) so the PDF download below can read them.
    # Cleared on logout, or overwritten on the next enrolment.
    codes = request.session.get(BACKUP_CODES_SESSION_KEY)
    return render(request, "accounts/backup_codes.html", {"codes": codes})


def download_backup_codes(request):
    if not request.user.is_authenticated:
        return redirect("accounts:login")
    codes = request.session.get(BACKUP_CODES_SESSION_KEY)
    if not codes:
        return redirect("accounts:backup_codes")

    buffer = io.BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter
    y = height - inch

    pdf.setFont("Helvetica-Bold", 18)
    pdf.drawString(inch, y, "doctorhide backup codes")
    y -= 0.4 * inch
    pdf.setFont("Helvetica", 10)
    pdf.drawString(inch, y, f"Account: {request.user.get_username()}")
    y -= 0.25 * inch
    pdf.drawString(inch, y, "Each code works once. Store this somewhere safe.")
    y -= 0.5 * inch

    pdf.setFont("Courier", 14)
    for code in codes:
        pdf.drawString(inch, y, code)
        y -= 0.32 * inch

    pdf.showPage()
    pdf.save()
    buffer.seek(0)
    return HttpResponse(
        buffer,
        content_type="application/pdf",
        headers={"Content-Disposition": 'attachment; filename="doctorhide-backup-codes.pdf"'},
    )


@otp_required
def settings_view(request):
    if request.method == "POST":
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            # Keep the current session valid after the password hash changes.
            update_session_auth_hash(request, user)
            return redirect("accounts:settings")
    else:
        form = PasswordChangeForm(request.user)

    return render(request, "accounts/settings.html", {"form": form})


def logout_view(request):
    auth_logout(request)
    return redirect("accounts:login")


@otp_required
def delete_account(request):
    """OTP-reauth-gated account deletion flow."""

    error = None
    success = False

    if request.method == "POST":
        token = request.POST.get("token", "").strip()
        # Re-authenticate the user via OTP token (must have confirmed TOTP).
        device = match_token(request.user, token)
        if device is None:
            error = "Invalid code."
        else:
            # Token verified. Now check org ownership constraints and handle
            # ServiceAccount.created_by foreign keys before deleting the user.
            from organizations.models import Membership
            from iam.models import ServiceAccount

            try:
                # Check if user is the last owner of any organization with other members.
                owner_memberships = Membership.objects.filter(
                    user=request.user, role=Membership.ROLE_OWNER
                ).select_related("organization")

                for membership in owner_memberships:
                    org = membership.organization
                    # Check if there are other owners in this org.
                    other_owners = Membership.objects.filter(
                        organization=org, role=Membership.ROLE_OWNER
                    ).exclude(user=request.user)

                    # If user is the sole owner AND there are other members, block.
                    if not other_owners.exists():
                        other_members = Membership.objects.filter(
                            organization=org
                        ).exclude(user=request.user)
                        if other_members.exists():
                            error = (
                                f"You are the last owner of '{org.name}' and it has "
                                f"other members. Please transfer ownership or remove "
                                f"the other members first."
                            )
                            break

                if not error:
                    # Check for service accounts created by this user.
                    # Since ServiceAccount.created_by has on_delete=PROTECT, we must
                    # handle them before deletion.
                    service_accounts = ServiceAccount.objects.filter(
                        created_by=request.user
                    )

                    if service_accounts.exists():
                        # For now, block deletion if user created service accounts.
                        # (Alternative: reassign to org owner, but that's more complex.)
                        error = (
                            "You have created service accounts that must be deleted "
                            "or reassigned before your account can be deleted."
                        )

                if not error:
                    # All checks passed. Delete the user and cascade.
                    username = request.user.get_username()
                    request.user.delete()
                    auth_logout(request)
                    success = True

            except Exception as exc:
                error = f"An error occurred: {str(exc)}"

    if success:
        return render(request, "accounts/delete_account_success.html")

    return render(request, "accounts/delete_account.html", {"error": error})


def _complete_login(request, user, device):
    request.session.pop(PENDING_SESSION_KEY, None)
    auth_login(request, user)
    otp_login(request, device)


def verify_email(request, token):
    """Verify email via token link from signup."""
    try:
        verification_token = EmailVerificationToken.objects.get(token=token)
    except EmailVerificationToken.DoesNotExist:
        return render(request, "accounts/verify_email_invalid.html")

    user = verification_token.user
    user.email_verified = True
    user.save()
    verification_token.delete()

    return render(request, "accounts/verify_email_success.html", {"username": user.username})


def _issue_backup_codes(user):
    """Replace any existing backup codes with a fresh set, returned in plaintext
    once for display."""
    StaticDevice.objects.filter(user=user, name="backup").delete()
    device = StaticDevice.objects.create(user=user, name="backup", confirmed=True)
    codes = []
    for _ in range(BACKUP_CODE_COUNT):
        token = StaticToken.random_token()
        device.token_set.create(token=token)
        codes.append(token)
    return codes


def reset_mfa_admin(user):
    """Admin action to reset a user's TOTP device and reissue backup codes.

    This is used for support/recovery when a user has lost their device.
    Returns the newly generated backup codes as plaintext (for admin to share).
    """
    # Delete the confirmed TOTP device to force re-enrollment.
    TOTPDevice.objects.filter(user=user, confirmed=True).delete()
    # Reissue backup codes.
    codes = _issue_backup_codes(user)
    return codes


def lost_mfa_device(request):
    """User-facing page for when they've lost their MFA device.

    Provides guidance on contacting support for MFA reset.
    """
    if not request.user.is_authenticated:
        return redirect("accounts:login")

    return render(request, "accounts/lost_mfa_device.html")
