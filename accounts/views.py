import base64
import io

import qrcode
from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth import login as auth_login
from django.contrib.auth import logout as auth_logout
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.http import HttpResponse
from django.shortcuts import redirect, render
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas
from django_otp import login as otp_login
from django_otp import match_token
from django_otp.plugins.otp_static.models import StaticDevice, StaticToken
from django_otp.plugins.otp_totp.models import TOTPDevice

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


def signup(request):
    if request.user.is_authenticated and request.user.is_verified():
        return redirect("vault:projects")

    errors = []
    username = ""
    if request.method == "POST":
        username = request.POST.get("username", "").strip()
        password1 = request.POST.get("password1", "")
        password2 = request.POST.get("password2", "")

        if not username:
            errors.append("Username is required.")
        elif User.objects.filter(username__iexact=username).exists():
            errors.append("That username is already taken.")
        if password1 != password2:
            errors.append("Passwords don't match.")

        if not errors:
            try:
                validate_password(password1)
            except ValidationError as exc:
                errors.extend(exc.messages)

        if not errors:
            user = User.objects.create_user(username=username, password=password1)
            # New humans must enrol TOTP before the account is usable.
            request.session[PENDING_SESSION_KEY] = user.pk
            return redirect("accounts:totp_enroll")

    return render(request, "accounts/signup.html", {"errors": errors, "username": username})


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


def logout_view(request):
    auth_logout(request)
    return redirect("accounts:login")


def _complete_login(request, user, device):
    request.session.pop(PENDING_SESSION_KEY, None)
    auth_login(request, user)
    otp_login(request, device)


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
