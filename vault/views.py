from django.contrib import messages
from django.http import Http404
from django.shortcuts import get_object_or_404, redirect, render
from django_otp.decorators import otp_required

from organizations.models import (
    Membership,
    Organization,
    membership_for,
    personal_organization,
)

from . import crypto
from .models import Project, ProjectAPIKey, Secret

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
                salt=salt,
                verifier=crypto.make_verifier(key),
            )
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
        },
    )


@otp_required
def project_unlock(request, public_id):
    project = _get_project(request, public_id)
    if request.method == "POST":
        passphrase = request.POST.get("passphrase", "")
        key = crypto.derive_key(passphrase, project.salt, project.iterations)
        if crypto.verify_key(key, project.verifier):
            _store_key(request, project, key)
        else:
            messages.error(request, "Wrong salt.")
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
