from django.contrib import messages
from django.contrib.sessions.backends.db import SessionStore
from django.contrib.sessions.models import Session
from django.db import transaction
from django.http import Http404
from django.shortcuts import get_object_or_404, redirect, render
from django_otp.decorators import otp_required

from organizations.models import (
    Membership,
    Organization,
    membership_for,
    personal_organization,
)

from . import audit, crypto
from .models import Project, ProjectAPIKey, Secret, SecretVersion

SESSION_KEYS = "vault_keys"  # {public_id: fernet_key_str} for unlocked projects
NEW_API_KEY_SESSION = "vault_new_api_key"
CURRENT_ORG_SESSION = "vault_current_org"  # selected organization id


def current_organization(request):
    """Resolve the organization the request is acting under.

    Prefers an explicit selection stored on the session; otherwise defaults to
    the first organization the user owns (creating a personal one if needed).
    """
    org_id = request.session.get(CURRENT_ORG_SESSION)
    if org_id is not None:
        org = Organization.objects.filter(
            id=org_id, memberships__user=request.user
        ).first()
        if org is not None:
            return org
    org = personal_organization(request.user)
    request.session[CURRENT_ORG_SESSION] = org.id
    return org


def _unlocked_key(request, project):
    raw = request.session.get(SESSION_KEYS, {}).get(project.public_id)
    return raw.encode() if raw else None


def _store_key(request, project, key: bytes):
    keys = request.session.get(SESSION_KEYS, {})
    keys[project.public_id] = key.decode()
    request.session[SESSION_KEYS] = keys


def _forget_key(request, project):
    keys = request.session.get(SESSION_KEYS, {})
    if keys.pop(project.public_id, None) is not None:
        request.session[SESSION_KEYS] = keys


def _get_project(request, public_id, required_role=Membership.ROLE_VIEWER):
    """Resolve a project the caller may act on, enforcing org-membership RBAC.

    The project must belong to an organization the caller is a member of, and
    that membership must be at least ``required_role``. Both non-membership and
    insufficient role surface as 404 so the tenant boundary never leaks whether
    a project exists. The resolved membership is stashed on the request for
    views/templates that vary on role.
    """
    project = get_object_or_404(
        Project, public_id=public_id, organization__memberships__user=request.user
    )
    membership = membership_for(request.user, project.organization)
    if membership is None or not membership.at_least(required_role):
        raise Http404("No such project.")
    request.current_membership = membership
    return project


@otp_required
def projects(request):
    org = current_organization(request)
    return render(
        request,
        "vault/projects.html",
        {"projects": Project.objects.filter(organization=org)},
    )


@otp_required
def project_create(request):
    org = current_organization(request)
    membership = membership_for(request.user, org)
    if membership is None or not membership.at_least(Membership.ROLE_ADMIN):
        raise Http404("No such organization.")
    error = None
    name = ""
    if request.method == "POST":
        name = request.POST.get("name", "").strip()
        passphrase = request.POST.get("passphrase", "")
        if not name:
            error = "Project name is required."
        elif len(passphrase) < 8:
            error = "Salt must be at least 8 characters."
        elif request.user.projects.filter(name=name).exists():
            error = "You already have a project with that name."
        else:
            salt = crypto.generate_salt()
            key = crypto.derive_key(passphrase, salt)
            project = Project.objects.create(
                owner=request.user,
                organization=org,
                public_id=Project.new_public_id(),
                name=name,
            )
            # The post_save signal auto-seeded a default Environment with
            # random (unrecoverable) crypto. Overwrite it with the user's
            # passphrase-derived crypto so the project is actually usable.
            # This is the legacy single-env project shape; Phase 3 will
            # expand this to seed three envs (development/staging/
            # production) with the user's passphrase.
            env = project.default_environment
            env.salt = salt
            env.verifier = crypto.make_verifier(key)
            env.save(update_fields=["salt", "verifier"])
            _store_key(request, project, key)  # auto-unlock after creation
            return redirect("vault:detail", public_id=project.public_id)

    return render(request, "vault/project_create.html", {"error": error, "name": name})


@otp_required
def project_detail(request, public_id):
    project = _get_project(request, public_id)
    key = _unlocked_key(request, project)

    secrets_view = []
    if key is not None:
        reveal_id = request.GET.get("reveal")
        for secret in project.secrets.filter(deleted_at__isnull=True):
            value = None
            if str(secret.id) == reveal_id:
                value = crypto.decrypt(key, secret.ciphertext)
            secrets_view.append({"obj": secret, "value": value})

    new_api_key = request.session.pop(NEW_API_KEY_SESSION, None)
    return render(
        request,
        "vault/project_detail.html",
        {
            "project": project,
            "unlocked": key is not None,
            "secrets": secrets_view,
            "api_keys": project.api_keys.all(),
            "new_api_key": new_api_key,
            "requires_rekey": project.requires_rekey,
        },
    )


@otp_required
def project_unlock(request, public_id):
    project = _get_project(request, public_id)
    # If an incident requires this project to be re-keyed, normal unlock
    # is disabled and the user is sent to the rekey flow instead. This
    # prevents an operator from accidentally using a passphrase the
    # response team has flagged as suspect.
    if project.requires_rekey:
        return redirect("vault:rekey", public_id=public_id)
    if request.method == "POST":
        passphrase = request.POST.get("passphrase", "")
        key = crypto.derive_key(passphrase, project.salt, project.iterations)
        if crypto.verify_key(key, project.verifier):
            _store_key(request, project, key)
        else:
            messages.error(request, "Wrong salt.")
            from .metrics import vault_unlock_failures_total

            vault_unlock_failures_total.labels(
                project_id=project.public_id
            ).inc()
    return redirect("vault:detail", public_id=public_id)


@otp_required
def project_lock(request, public_id):
    project = _get_project(request, public_id)
    _forget_key(request, project)
    return redirect("vault:detail", public_id=public_id)


@otp_required
def secret_add(request, public_id):
    project = _get_project(request, public_id, required_role=Membership.ROLE_MEMBER)
    key = _unlocked_key(request, project)
    if key is None:
        messages.error(request, "Unlock the project first.")
        return redirect("vault:detail", public_id=public_id)
    if request.method == "POST":
        secret_key = request.POST.get("key", "").strip()
        value = request.POST.get("value", "")
        if not secret_key or not value:
            messages.error(request, "Both key and value are required.")
        else:
            Secret.objects.update_or_create(
                project=project,
                key=secret_key,
                defaults={"ciphertext": crypto.encrypt(key, value)},
            )
    return redirect("vault:detail", public_id=public_id)


@otp_required
def secret_delete(request, public_id, secret_id):
    project = _get_project(request, public_id, required_role=Membership.ROLE_MEMBER)
    if request.method == "POST":
        secret = project.secrets.filter(id=secret_id, deleted_at__isnull=True).first()
        if secret:
            secret.soft_delete()
    return redirect("vault:detail", public_id=public_id)


@otp_required
def api_key_create(request, public_id):
    project = _get_project(request, public_id, required_role=Membership.ROLE_ADMIN)
    if request.method == "POST":
        _, token = ProjectAPIKey.generate(project, name=request.POST.get("name", "").strip())
        request.session[NEW_API_KEY_SESSION] = token  # shown once on the detail page
    return redirect("vault:detail", public_id=public_id)


@otp_required
def api_key_revoke(request, public_id, key_id):
    project = _get_project(request, public_id, required_role=Membership.ROLE_ADMIN)
    if request.method == "POST":
        api_key = project.api_keys.filter(id=key_id).first()
        if api_key:
            api_key.revoke()
    return redirect("vault:detail", public_id=public_id)


@otp_required
def secret_versions(request, public_id, secret_id):
    project = _get_project(request, public_id)
    key = _unlocked_key(request, project)
    secret = project.secrets.filter(id=secret_id).first()
    if secret is None:
        raise Http404("Secret not found.")

    versions = []
    if key is not None:
        reveal_id = request.GET.get("reveal")
        for version in secret.versions.all():
            value = None
            if str(version.id) == reveal_id:
                value = crypto.decrypt(key, version.ciphertext)
            versions.append({"obj": version, "value": value})

    return render(
        request,
        "vault/secret_versions.html",
        {
            "project": project,
            "secret": secret,
            "unlocked": key is not None,
            "versions": versions,
        },
    )


@otp_required
def secret_version_restore(request, public_id, secret_id, version_id):
    project = _get_project(request, public_id, required_role=Membership.ROLE_MEMBER)
    secret = project.secrets.filter(id=secret_id).first()
    if secret is None:
        raise Http404("Secret not found.")

    if request.method == "POST":
        version = secret.versions.filter(id=version_id).first()
        if version:
            # Restore by updating the secret's ciphertext and creating a new version.
            secret.ciphertext = version.ciphertext
            secret.save(update_fields=["ciphertext"])
            SecretVersion.objects.create(
                secret=secret,
                ciphertext=version.ciphertext,
                label=f"Restored from v{version.id}",
            )
            messages.success(request, "Version restored.")

    return redirect("vault:secret_versions", public_id=public_id, secret_id=secret_id)


def _forget_project_in_all_sessions(public_id: str) -> int:
    """Remove any cached unlock key for ``public_id`` from every session row.

    The session store is a per-user cache of derived Fernet keys (see
    ``_unlocked_key``). After a rekey, every cached entry pointing at the
    old key is wrong and must be dropped, otherwise a stale session could
    attempt to read re-encrypted ciphertexts with the obsolete key and the
    user would see empty/garbled reveals instead of clean errors.

    Returns the number of session rows touched, for audit logging.
    """
    touched = 0
    for session in Session.objects.all():
        # The whole per-row block is guarded: a malformed/expired row
        # (e.g. garbage ``session_data`` from a botched migration, an
        # expired session whose key has been recycled, or a future
        # pickle format change) must never break the rekey. The ``except``
        # covers the ``SessionStore`` construction *and* the
        # ``store.get(SESSION_KEYS)`` decode, because the decode can
        # raise ``binascii.Error`` / ``pickle.UnpicklingError`` / etc.
        # on a corrupt row.
        try:
            store = SessionStore(session_key=session.session_key)
            keys = store.get(SESSION_KEYS)
        except Exception:
            continue
        if not isinstance(keys, dict):
            continue
        if public_id in keys:
            keys = dict(keys)
            keys.pop(public_id, None)
            store[SESSION_KEYS] = keys
            store.save()
            touched += 1
    return touched


def _reencrypt_project(project, old_key, new_key) -> tuple[int, int]:
    """Re-encrypt every live Secret and every SecretVersion under ``new_key``.

    Decrypts with ``old_key``, encrypts with ``new_key``, and saves the
    updated ciphertext on the existing row (no version churn). Returns
    ``(secret_count, version_count)``. Must be called inside an outer
    ``transaction.atomic()`` so that a mid-iteration failure rolls back
    all of the writes in one shot.
    """
    secrets = list(project.secrets.filter(deleted_at__isnull=True))
    for secret in secrets:
        plaintext = crypto.decrypt(old_key, secret.ciphertext)
        secret.ciphertext = crypto.encrypt(new_key, plaintext)
        secret.save(update_fields=["ciphertext"])

    version_count = 0
    for secret in project.secrets.all():
        for version in secret.versions.all():
            plaintext = crypto.decrypt(old_key, version.ciphertext)
            version.ciphertext = crypto.encrypt(new_key, plaintext)
            version.save(update_fields=["ciphertext"])
            version_count += 1

    return len(secrets), version_count


def _validate_rekey_form(post_data) -> str | None:
    """Return None if the rekey form's inputs are consistent, or a
    user-facing error string. Pulled out of ``project_rekey`` to keep the
    view's complexity below the project lint threshold."""
    old_passphrase = post_data.get("old_passphrase", "")
    new_passphrase = post_data.get("new_passphrase", "")
    new_passphrase_confirm = post_data.get("new_passphrase_confirm", "")

    if not old_passphrase or not new_passphrase:
        return "Both the current and new passphrases are required."
    if new_passphrase != new_passphrase_confirm:
        return "The two new passphrase entries do not match."
    if len(new_passphrase) < 8:
        return "New passphrase must be at least 8 characters."
    return None


@otp_required
def project_rekey(request, public_id):
    """Forced or voluntary passphrase rotation for a project.

    GET shows a form asking for the *current* passphrase (to prove the
    caller can still decrypt the existing data) and a *new* passphrase
    (the one to rotate to). POST re-derives a fresh key from the new
    passphrase, re-encrypts every ``Secret.ciphertext`` and every
    ``SecretVersion.ciphertext`` under the new key, rotates
    ``Project.salt``/``Project.verifier``/``Project.iterations``, and
    invalidates every cached unlock key for the project across all
    active sessions.

    The view is destructive: a corrupt ciphertext, a wrong old passphrase,
    or a write failure all roll the whole operation back. A successful
    rekey emits an ``AuditEvent(action='project.rekey')`` row carrying
    the number of secrets and version rows rotated, plus the number of
    sessions that were invalidated. The rekey flag (``requires_rekey``)
    is cleared at the end of a successful rotation.
    """
    project = _get_project(request, public_id, required_role=Membership.ROLE_OWNER)

    error = None
    if request.method == "POST":
        error = _validate_rekey_form(request.POST)
        if error is None:
            old_passphrase = request.POST["old_passphrase"]
            new_passphrase = request.POST["new_passphrase"]
            old_key = crypto.derive_key(
                old_passphrase, project.salt, project.iterations
            )
            if not crypto.verify_key(old_key, project.verifier):
                audit.record(
                    request,
                    "project.rekey",
                    "denied:wrong_old_passphrase",
                    project=project,
                )
                error = "Current passphrase is incorrect."
            else:
                new_salt = crypto.generate_salt()
                new_key = crypto.derive_key(
                    new_passphrase, new_salt, project.iterations
                )
                try:
                    with transaction.atomic():
                        secret_count, version_count = _reencrypt_project(
                            project, old_key, new_key
                        )
                        env = project.default_environment
                        env.salt = new_salt
                        env.verifier = crypto.make_verifier(new_key)
                        env.requires_rekey = False
                        env.save(
                            update_fields=["salt", "verifier", "requires_rekey"]
                        )
                except crypto.InvalidFernetToken:
                    audit.record(
                        request,
                        "project.rekey",
                        "failed:ciphertext_corrupt",
                        project=project,
                    )
                    error = (
                        "Could not re-encrypt every secret. The project "
                        "was not modified; contact support."
                    )
                else:
                    sessions_touched = _forget_project_in_all_sessions(
                        project.public_id
                    )
                    # Drop the unlock key from the current session too.
                    _forget_key(request, project)
                    audit.record(
                        request,
                        "project.rekey",
                        "success",
                        project=project,
                        secret_key=(
                            f"secrets={secret_count};versions={version_count};"
                            f"sessions_invalidated={sessions_touched}"
                        ),
                    )
                    messages.success(
                        request,
                        "Passphrase rotated. The project is locked; "
                        "use your new passphrase to unlock it.",
                    )
                    return redirect("vault:detail", public_id=public_id)

    return render(
        request,
        "vault/project_rekey.html",
        {
            "project": project,
            "error": error,
            "requires_rekey": project.requires_rekey,
        },
    )
