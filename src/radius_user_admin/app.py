from __future__ import annotations

import csv
import io
import ipaddress
import json
import os
import secrets
import smtplib
import ssl
import time
from collections import defaultdict, deque
from datetime import UTC, datetime, timedelta
from email.message import EmailMessage
from pathlib import Path
from urllib.parse import quote
from zoneinfo import ZoneInfo

from fastapi import FastAPI, Form, Request
from fastapi.responses import PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

try:
    import segno
except ImportError:  # pragma: no cover - QR codes are an optional enhancement
    segno = None

from .helper_client import HelperError, call_helper

BASE = Path(__file__).resolve().parent
SESSION_TTL = 30 * 60
LOGIN_WINDOW = 10 * 60
LOGIN_LIMIT = 5
LOGIN_LOCKOUT = 15 * 60
LOCAL_ZONE = ZoneInfo("Europe/Madrid")
LOGIN_ATTEMPTS: dict[str, deque[float]] = defaultdict(deque)
LOGIN_LOCKED_UNTIL: dict[str, float] = {}
ALLOWED_HOSTS = [
    host.strip()
    for host in os.environ.get(
        "RADIUS_ADMIN_ALLOWED_HOSTS",
        "radius.your-domain.com,127.0.0.1,localhost,testserver",
    ).split(",")
    if host.strip()
]
ORGANIZATION = os.environ.get("RADIUS_ADMIN_ORGANIZATION", "Your Organization").strip()


def common_template_context(_request: Request) -> dict[str, str]:
    return {"organization": ORGANIZATION or "Your Organization"}

app = FastAPI(title="RadiusPilot", docs_url=None, redoc_url=None)
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=ALLOWED_HOSTS,
)
app.add_middleware(
    SessionMiddleware,
    secret_key=os.environ.get("RADIUS_ADMIN_SESSION_SECRET", secrets.token_hex(32)),
    https_only=os.environ.get("RADIUS_ADMIN_SECURE_COOKIE", "1") == "1",
    same_site="strict",
    max_age=SESSION_TTL,
)
app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")
templates = Jinja2Templates(
    directory=BASE / "templates", context_processors=[common_template_context]
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    if not request.url.path.startswith("/static/"):
        response.headers["Cache-Control"] = "no-store"
    return response


def source_ip(request: Request) -> str:
    candidate = request.headers.get("x-real-ip") or (request.client.host if request.client else "")
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return "unknown"


def csrf_token(request: Request) -> str:
    token = request.session.get("csrf")
    if not token:
        token = secrets.token_urlsafe(32)
        request.session["csrf"] = token
    return token


def check_csrf(request: Request, token: str) -> None:
    expected = request.session.get("csrf", "")
    if not expected or not secrets.compare_digest(expected, token):
        raise HelperError("The form expired. Refresh the page and try again.")


def current_admin(request: Request) -> str | None:
    if hasattr(request.state, "current_admin"):
        return request.state.current_admin
    admin = request.session.get("admin")
    last_seen = request.session.get("last_seen", 0)
    if not admin:
        request.state.current_admin = None
        return None
    if not isinstance(last_seen, (int, float)) or time.time() - last_seen > SESSION_TTL:
        request.session.clear()
        request.state.current_admin = None
        return None
    try:
        if not call_helper("panel-status", {"username": admin}).get("panel_access"):
            request.session.clear()
            request.state.current_admin = None
            return None
    except HelperError:
        request.session.clear()
        request.state.current_admin = None
        return None
    request.session["last_seen"] = time.time()
    request.state.current_admin = str(admin)
    return request.state.current_admin


def require_admin(request: Request) -> str | RedirectResponse:
    admin = current_admin(request)
    if not admin:
        return RedirectResponse("/login", status_code=303)
    return admin


def redirect(
    request: Request, message: str, level: str = "success", anchor: str = ""
) -> RedirectResponse:
    """Store user feedback server-side and redirect only to a fixed local path."""
    request.session["flash"] = {
        "message": str(message)[:500],
        "level": level if level in {"success", "danger", "warning"} else "success",
    }
    destinations = {"": "/", "users": "/#users", "system": "/#system"}
    return RedirectResponse(destinations.get(anchor, "/"), status_code=303)


def helper_payload(request: Request, payload: dict[str, object]) -> dict[str, object]:
    return {
        **payload,
        "_actor": current_admin(request) or "unknown",
        "_source_ip": source_ip(request),
    }


def utc_form_time(value: str) -> str | None:
    raw = value.strip()
    if not raw:
        return None
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError as exc:
        raise HelperError("Enter a valid date and time.") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=LOCAL_ZONE)
    return parsed.astimezone(UTC).isoformat(timespec="seconds")


def access_policy_payload(mode: str, rules_json: str) -> dict[str, object]:
    clean_mode = mode.strip().lower()
    if clean_mode == "full":
        return {"mode": "full", "rules": []}
    if clean_mode != "custom":
        raise HelperError("Choose full or custom network access.")
    if len(rules_json) > 12000:
        raise HelperError("The custom access policy is too large.")
    try:
        rules = json.loads(rules_json)
    except json.JSONDecodeError as exc:
        raise HelperError("The custom access rules are invalid.") from exc
    if not isinstance(rules, list):
        raise HelperError("The custom access rules are invalid.")
    return {"mode": "custom", "rules": rules}


def qr_data_uri(value: str) -> str | None:
    if segno is None:
        return None
    try:
        return segno.make(value, error="m").svg_data_uri(scale=4, border=2)
    except (ValueError, TypeError):
        return None


def invitation_url(request: Request, token: str) -> str:
    configured = os.environ.get("RADIUS_ADMIN_PUBLIC_URL", "").rstrip("/")
    base = configured or str(request.base_url).rstrip("/")
    if not base.startswith(("https://", "http://testserver")):
        raise HelperError("The configured public URL must use HTTPS.")
    return f"{base}/invite/{quote(token, safe='')}"


def send_invitation_email(recipient: str, username: str, url: str, expires_at: str) -> bool:
    host = os.environ.get("RADIUS_ADMIN_SMTP_HOST", "").strip()
    if not host or not recipient:
        return False
    try:
        port = int(os.environ.get("RADIUS_ADMIN_SMTP_PORT", "587"))
    except ValueError as exc:
        raise HelperError("The SMTP port is invalid.") from exc
    message = EmailMessage()
    message["Subject"] = "Your RadiusPilot VPN invitation"
    message["From"] = os.environ.get(
        "RADIUS_ADMIN_SMTP_FROM", "RadiusPilot <radiuspilot@your-domain.com>"
    )
    message["To"] = recipient
    message.set_content(
        "\n".join(
            [
                f"Hello {username},",
                "",
                "Use this one-time link from an approved LAN or VPN network to finish setup:",
                url,
                "",
                f"The invitation expires at {expires_at}.",
                "If you were not expecting this invitation, ignore this message.",
            ]
        )
    )
    try:
        with smtplib.SMTP(host, port, timeout=10) as smtp:
            if os.environ.get("RADIUS_ADMIN_SMTP_STARTTLS", "1") == "1":
                smtp.starttls(context=ssl.create_default_context())
            username_env = os.environ.get("RADIUS_ADMIN_SMTP_USERNAME", "")
            password_env = os.environ.get("RADIUS_ADMIN_SMTP_PASSWORD", "")
            if username_env:
                smtp.login(username_env, password_env)
            smtp.send_message(message)
    except (OSError, smtplib.SMTPException) as exc:
        raise HelperError("The invitation was created, but email delivery failed.") from exc
    return True


@app.get("/login")
def login_page(request: Request):
    if current_admin(request):
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse(
        request,
        "login.html",
        {"csrf": csrf_token(request), "error": request.session.pop("login_error", "")},
    )


@app.post("/login")
def login(
    request: Request,
    csrf: str = Form(),
    username: str = Form(),
    password: str = Form(),
):
    try:
        check_csrf(request, csrf)
    except HelperError as exc:
        request.session["login_error"] = str(exc)[:500]
        return RedirectResponse("/login", status_code=303)
    ip = source_ip(request)
    current = time.time()
    if LOGIN_LOCKED_UNTIL.get(ip, 0) > current:
        request.session["login_error"] = "Too many attempts. Try again later."
        return RedirectResponse("/login", status_code=303)
    attempts = LOGIN_ATTEMPTS[ip]
    while attempts and current - attempts[0] > LOGIN_WINDOW:
        attempts.popleft()
    try:
        result = call_helper(
            "authenticate-admin",
            {"username": username, "password": password, "_source_ip": ip},
        )
    except HelperError:
        result = {"authenticated": False}
    if not result.get("authenticated"):
        attempts.append(current)
        if len(attempts) >= LOGIN_LIMIT:
            LOGIN_LOCKED_UNTIL[ip] = current + LOGIN_LOCKOUT
            attempts.clear()
        request.session["login_error"] = "Invalid credentials."
        return RedirectResponse("/login", status_code=303)
    LOGIN_ATTEMPTS.pop(ip, None)
    LOGIN_LOCKED_UNTIL.pop(ip, None)
    request.session.clear()
    request.session.update(
        {"admin": username.strip().lower(), "last_seen": current, "csrf": secrets.token_urlsafe(32)}
    )
    return RedirectResponse("/", status_code=303)


@app.post("/logout")
def logout(request: Request, csrf: str = Form(default="")):
    # Ending your own session is safe, so an expired or missing CSRF token must
    # still log out cleanly instead of failing with a server error.
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


@app.get("/")
def index(request: Request):
    admin = require_admin(request)
    if isinstance(admin, RedirectResponse):
        return admin
    error = ""
    try:
        data = call_helper("list")
        activity = call_helper("audit")
        backups = call_helper("backups")["backups"]
        invitations = call_helper("invite-list")["invitations"]
        users = data["users"]
        health = data["health"]
        access_policy = data.get(
            "access_policy", {"custom_enabled": False, "allowed_destinations": []}
        )
        duo_enrollment_api = data.get(
            "duo_enrollment_api",
            {"configured": False, "api_host": "", "ikey_hint": ""},
        )
    except HelperError as exc:
        users, backups, invitations, error = [], [], [], str(exc)
        activity = {"events": [], "auth_events": []}
        health = {
            "active": False,
            "config_valid": False,
            "duo_active": False,
            "nginx_active": False,
            "certificate": {"valid": False, "days_remaining": None},
            "last_backup": None,
            "disk_free_mb": None,
        }
        access_policy = {"custom_enabled": False, "allowed_destinations": []}
        duo_enrollment_api = {"configured": False, "api_host": "", "ikey_hint": ""}
    expiry_warning = datetime.now(UTC) + timedelta(days=7)
    for user in users:
        user["expires_soon"] = False
        raw_expiry = user.get("expires_at")
        if not raw_expiry or not user.get("effective_enabled"):
            continue
        try:
            expires = datetime.fromisoformat(raw_expiry)
        except ValueError:
            continue
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=UTC)
        user["expires_soon"] = expires <= expiry_warning
    flash = request.session.pop("flash", {})
    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "admin": admin,
            "users": users,
            "health": health,
            "audit_events": activity["events"],
            "auth_events": activity["auth_events"],
            "backups": backups,
            "invitations": invitations,
            "message": str(flash.get("message", "")),
            "level": str(flash.get("level", "success")),
            "error": error,
            "csrf": csrf_token(request),
            "enabled_count": sum(user["effective_enabled"] for user in users),
            "blocked_count": sum(not user["effective_enabled"] for user in users),
            "duo_count": sum(
                user["effective_enabled"] and user["effective_duo_required"] for user in users
            ),
            "password_only_count": sum(
                user["effective_enabled"] and not user["effective_duo_required"] for user in users
            ),
            "panel_admin_count": sum(user["panel_access"] for user in users),
            "expiring_count": sum(user["expires_soon"] for user in users),
            "custom_access_enabled": bool(access_policy.get("custom_enabled")),
            "allowed_policy_destinations": access_policy.get("allowed_destinations", []),
            "access_objects": access_policy.get("objects", []),
            "duo_enrollment_api": duo_enrollment_api,
            "avpair_forwarding": bool(access_policy.get("avpair_forwarding")),
            "custom_gate_enabled": bool(access_policy.get("gate_enabled")),
            "smtp_configured": bool(os.environ.get("RADIUS_ADMIN_SMTP_HOST", "").strip()),
            "legacy_count": sum(
                user.get("credential_scheme") == "legacy-cleartext" for user in users
            ),
        },
    )


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/invitations")
def create_invitation(
    request: Request,
    csrf: str = Form(),
    username: str = Form(),
    email: str = Form(default=""),
    duo_required: bool = Form(default=True),
    valid_hours: int = Form(default=24),
    access_mode: str = Form(default="full"),
    access_rules: str = Form(default="[]"),
):
    admin = require_admin(request)
    if isinstance(admin, RedirectResponse):
        return admin
    try:
        check_csrf(request, csrf)
        access_policy = access_policy_payload(access_mode, access_rules)
        result = call_helper(
            "invite-create",
            helper_payload(
                request,
                {
                    "username": username,
                    "email": email,
                    "duo_required": duo_required,
                    "valid_hours": valid_hours,
                    "access_policy": access_policy,
                },
            ),
        )["invitation"]
        url = invitation_url(request, result["token"])
        delivered = send_invitation_email(
            result["email"], result["username"], url, result["expires_at"]
        )
    except HelperError as exc:
        return redirect(request, str(exc), "danger", "users")
    return templates.TemplateResponse(
        request,
        "invitation_created.html",
        {
            "admin": admin,
            "csrf": csrf_token(request),
            "username": result["username"],
            "email": result["email"],
            "expires_at": result["expires_at"],
            "invitation_url": url,
            "invitation_qr": qr_data_uri(url),
            "delivered": delivered,
        },
    )


@app.post("/invitations/{username}/revoke")
def revoke_invitation(username: str, request: Request, csrf: str = Form()):
    return mutate(request, csrf, "invite-revoke", {"username": username})


@app.get("/invite/{token}")
def invitation_page(token: str, request: Request):
    try:
        invitation = call_helper("invite-status", {"token": token})["invitation"]
    except HelperError as exc:
        return templates.TemplateResponse(
            request,
            "invite_accept.html",
            {"error": str(exc), "csrf": csrf_token(request), "token": ""},
            status_code=410,
        )
    return templates.TemplateResponse(
        request,
        "invite_accept.html",
        {
            "error": "",
            "csrf": csrf_token(request),
            "token": token,
            "invitation": invitation,
        },
    )


@app.post("/invite/{token}")
def accept_invitation(
    token: str,
    request: Request,
    csrf: str = Form(),
    password: str = Form(),
    password_confirm: str = Form(),
):
    try:
        check_csrf(request, csrf)
        if not secrets.compare_digest(password, password_confirm):
            raise HelperError("The passwords do not match.")
        result = call_helper(
            "invite-accept",
            {"token": token, "password": password, "_source_ip": source_ip(request)},
        )["invitation"]
    except HelperError as exc:
        try:
            invitation = call_helper("invite-status", {"token": token})["invitation"]
        except HelperError:
            invitation = None
        return templates.TemplateResponse(
            request,
            "invite_accept.html",
            {
                "error": str(exc),
                "csrf": csrf_token(request),
                "token": token,
                "invitation": invitation,
            },
            status_code=400,
        )
    enrollment = result.get("enrollment") or {}
    return templates.TemplateResponse(
        request,
        "invite_complete.html",
        {
            "username": result["username"],
            "duo_required": result["duo_required"],
            "duo_warning": result.get("duo_warning", ""),
            "activation_url": enrollment.get("activation_url", ""),
            "activation_barcode": enrollment.get("activation_barcode", ""),
        },
    )


def mutate(
    request: Request,
    token: str,
    operation: str,
    payload: dict[str, object],
    *,
    anchor: str = "users",
):
    admin = require_admin(request)
    if isinstance(admin, RedirectResponse):
        return admin
    try:
        check_csrf(request, token)
        call_helper(operation, helper_payload(request, payload))
        return redirect(
            request, "Change applied and authentication services validated.", anchor=anchor
        )
    except HelperError as exc:
        return redirect(request, str(exc), "danger", anchor)


@app.post("/users")
def create_user(
    request: Request,
    csrf: str = Form(),
    username: str = Form(),
    password: str = Form(),
    duo_required: bool = Form(),
    expires_at: str = Form(default=""),
    duo_bypass_until: str = Form(default=""),
    duo_bypass_reason: str = Form(default=""),
    panel_access: bool = Form(default=False),
    panel_password: str = Form(default=""),
    access_mode: str = Form(default="full"),
    access_rules: str = Form(default="[]"),
):
    try:
        admin = require_admin(request)
        if isinstance(admin, RedirectResponse):
            return admin
        check_csrf(request, csrf)
        account_expiry = utc_form_time(expires_at)
        bypass_expiry = utc_form_time(duo_bypass_until)
        access_policy = access_policy_payload(access_mode, access_rules)
    except HelperError as exc:
        return redirect(request, str(exc), "danger", "users")
    enrollment_needed = False
    if duo_required or panel_access:
        try:
            readiness = call_helper(
                "duo-check", helper_payload(request, {"username": username})
            )["duo"]
            enrollment_needed = readiness.get("result") == "enroll"
            if panel_access and enrollment_needed:
                return redirect(
                    request,
                    "Create the VPN user, complete Duo enrollment, then grant panel access.",
                    "warning",
                    "users",
                )
            if not enrollment_needed and (
                readiness.get("result") != "auth" or not readiness.get("push_capable")
            ):
                return redirect(
                    request,
                    f"Duo is not ready for {username}: "
                    f"{readiness.get('status', 'unknown status')}.",
                    "danger",
                    "users",
                )
        except HelperError as exc:
            return redirect(request, str(exc), "danger", "users")
    payload = {
        "username": username,
        "password": password,
        "duo_required": duo_required,
        "expires_at": account_expiry,
        "duo_bypass_until": bypass_expiry,
        "duo_bypass_reason": duo_bypass_reason,
        "panel_access": panel_access,
        "panel_password": panel_password,
        "access_policy": access_policy,
    }
    try:
        call_helper("create", helper_payload(request, payload))
        if enrollment_needed:
            call_helper("duo-enroll", helper_payload(request, {"username": username}))
            request.session["enrollment_username"] = username.strip().lower()
            return RedirectResponse("/duo-enrollment", status_code=303)
        return redirect(
            request, "User created and authentication services validated.", anchor="users"
        )
    except HelperError as exc:
        if enrollment_needed:
            return redirect(
                request,
                f"Check the user list. Duo enrollment did not complete: {exc}",
                "danger",
                "users",
            )
        return redirect(request, str(exc), "danger", "users")


@app.post("/users/{username}/rename")
def rename_user(
    username: str,
    request: Request,
    csrf: str = Form(),
    new_username: str = Form(),
):
    admin = require_admin(request)
    if isinstance(admin, RedirectResponse):
        return admin
    try:
        check_csrf(request, csrf)
        user = next(item for item in call_helper("list")["users"] if item["username"] == username)
        if user["effective_duo_required"]:
            readiness = call_helper(
                "duo-check", helper_payload(request, {"username": new_username})
            )["duo"]
            if readiness.get("result") != "auth" or not readiness.get("push_capable"):
                return redirect(
                    request,
                    f"Duo is not ready for {new_username}: "
                    f"{readiness.get('status', 'unknown status')}.",
                    "danger",
                    "users",
                )
    except (HelperError, StopIteration) as exc:
        return redirect(request, str(exc) or "User not found.", "danger", "users")
    return mutate(request, csrf, "rename", {"username": username, "new_username": new_username})


@app.post("/users/{username}/password")
def reset_password(
    username: str,
    request: Request,
    csrf: str = Form(),
    password: str = Form(),
):
    return mutate(request, csrf, "reset-password", {"username": username, "password": password})


@app.post("/users/{username}/credential")
def migrate_password(username: str, request: Request, csrf: str = Form()):
    return mutate(request, csrf, "migrate-passwords", {"username": username})


@app.post("/users/{username}/status")
def set_status(
    username: str,
    request: Request,
    csrf: str = Form(),
    enabled: bool = Form(),
):
    return mutate(request, csrf, "set-enabled", {"username": username, "enabled": enabled})


@app.post("/users/{username}/duo")
def set_duo(
    username: str,
    request: Request,
    csrf: str = Form(),
    duo_required: bool = Form(),
    duo_bypass_until: str = Form(default=""),
    duo_bypass_reason: str = Form(default=""),
):
    try:
        admin = require_admin(request)
        if isinstance(admin, RedirectResponse):
            return admin
        check_csrf(request, csrf)
        if duo_required:
            readiness = call_helper(
                "duo-check", helper_payload(request, {"username": username})
            )["duo"]
            if readiness.get("result") != "auth" or not readiness.get("push_capable"):
                return redirect(
                    request,
                    f"Duo is not ready for {username}: "
                    f"{readiness.get('status', 'unknown status')}.",
                    "danger",
                    "users",
                )
        bypass_expiry = utc_form_time(duo_bypass_until)
    except HelperError as exc:
        return redirect(request, str(exc), "danger", "users")
    return mutate(
        request,
        csrf,
        "set-duo",
        {
            "username": username,
            "duo_required": duo_required,
            "duo_bypass_until": bypass_expiry,
            "duo_bypass_reason": duo_bypass_reason,
        },
    )


@app.post("/users/{username}/expiry")
def set_expiry(
    username: str,
    request: Request,
    csrf: str = Form(),
    expires_at: str = Form(default=""),
):
    try:
        expiry = utc_form_time(expires_at)
    except HelperError as exc:
        return redirect(request, str(exc), "danger", "users")
    return mutate(request, csrf, "set-expiry", {"username": username, "expires_at": expiry})


@app.post("/users/{username}/access")
def set_access_policy(
    username: str,
    request: Request,
    csrf: str = Form(),
    access_mode: str = Form(),
    access_rules: str = Form(default="[]"),
):
    try:
        policy = access_policy_payload(access_mode, access_rules)
    except HelperError as exc:
        return redirect(request, str(exc), "danger", "users")
    return mutate(
        request,
        csrf,
        "set-access-policy",
        {"username": username, "access_policy": policy},
    )


@app.post("/settings/duo-enrollment")
def set_duo_enrollment_api(
    request: Request,
    csrf: str = Form(),
    ikey: str = Form(),
    skey: str = Form(),
    api_host: str = Form(),
):
    return mutate(
        request,
        csrf,
        "set-duo-enroll-api",
        {"ikey": ikey, "skey": skey, "api_host": api_host},
        anchor="system",
    )


@app.post("/access-objects")
def save_access_object(
    request: Request,
    csrf: str = Form(),
    name: str = Form(),
    description: str = Form(default=""),
    object_rules: str = Form(default="[]"),
):
    if len(object_rules) > 12000:
        return redirect(request, "The object rules are too large.", "danger", "users")
    try:
        rules = json.loads(object_rules)
    except json.JSONDecodeError:
        return redirect(request, "The object rules are invalid.", "danger", "users")
    if not isinstance(rules, list):
        return redirect(request, "The object rules are invalid.", "danger", "users")
    return mutate(
        request,
        csrf,
        "object-set",
        {"name": name, "description": description, "rules": rules},
    )


@app.post("/access-objects/{name}/delete")
def delete_access_object(name: str, request: Request, csrf: str = Form()):
    return mutate(request, csrf, "object-delete", {"name": name})


@app.get("/access-objects/export")
def export_access_objects(request: Request):
    admin = require_admin(request)
    if isinstance(admin, RedirectResponse):
        return admin
    try:
        objects = call_helper("list", helper_payload(request, {}))["access_policy"]["objects"]
    except HelperError as exc:
        return redirect(request, str(exc), "danger", "users")
    payload = [
        {"name": item["name"], "description": item["description"], "rules": item["rules"]}
        for item in objects
    ]
    return Response(
        content=json.dumps({"access_objects": payload}, indent=2) + "\n",
        media_type="application/json",
        headers={"Content-Disposition": 'attachment; filename="access-objects.json"'},
    )


@app.post("/access-objects/import")
def import_access_objects(request: Request, csrf: str = Form(), objects_json: str = Form()):
    if len(objects_json) > 60000:
        return redirect(request, "The import is too large.", "danger", "users")
    try:
        parsed = json.loads(objects_json)
    except json.JSONDecodeError:
        return redirect(request, "The import is not valid JSON.", "danger", "users")
    objects = parsed.get("access_objects") if isinstance(parsed, dict) else parsed
    if not isinstance(objects, list):
        return redirect(request, "The import must be a list of access objects.", "danger", "users")
    return mutate(request, csrf, "object-import", {"objects": objects})


@app.post("/users/{username}/duo-check")
def check_duo(username: str, request: Request, csrf: str = Form()):
    admin = require_admin(request)
    if isinstance(admin, RedirectResponse):
        return admin
    try:
        check_csrf(request, csrf)
        duo = call_helper(
            "duo-check", helper_payload(request, {"username": username})
        )["duo"]
        capability = "Push ready" if duo["push_capable"] else "no Push-capable device"
        return redirect(
            request,
            f"Duo {duo['status']}; {duo['device_count']} device(s), {capability}.",
            "success" if duo["result"] == "auth" and duo["push_capable"] else "warning",
            "users",
        )
    except HelperError as exc:
        return redirect(request, str(exc), "danger", "users")


@app.post("/users/{username}/duo-enroll")
def enroll_duo(username: str, request: Request, csrf: str = Form()):
    admin = require_admin(request)
    if isinstance(admin, RedirectResponse):
        return admin
    try:
        check_csrf(request, csrf)
        call_helper("duo-enroll", helper_payload(request, {"username": username}))
        request.session["enrollment_username"] = username
        return RedirectResponse("/duo-enrollment", status_code=303)
    except HelperError as exc:
        return redirect(request, str(exc), "danger", "users")


@app.post("/users/{username}/duo-enrollment")
def select_duo_enrollment(username: str, request: Request, csrf: str = Form()):
    admin = require_admin(request)
    if isinstance(admin, RedirectResponse):
        return admin
    try:
        check_csrf(request, csrf)
        call_helper("duo-enrollment", {"username": username})
        request.session["enrollment_username"] = username
        return RedirectResponse("/duo-enrollment", status_code=303)
    except HelperError as exc:
        return redirect(request, str(exc), "danger", "users")


@app.get("/duo-enrollment")
def duo_enrollment_page(request: Request):
    admin = require_admin(request)
    if isinstance(admin, RedirectResponse):
        return admin
    username = str(request.session.pop("enrollment_username", ""))
    if not username:
        return redirect(request, "Choose a user enrollment first.", "warning", "users")
    try:
        enrollment = call_helper("duo-enrollment", {"username": username})["enrollment"]
        expires_at = datetime.fromtimestamp(int(enrollment["expiration"]), UTC).astimezone(
            LOCAL_ZONE
        )
    except (HelperError, KeyError, TypeError, ValueError, OSError) as exc:
        return redirect(
            request, str(exc) or "Duo enrollment is unavailable.", "danger", "users"
        )
    return templates.TemplateResponse(
        request,
        "duo_enrollment.html",
        {
            "admin": admin,
            "csrf": csrf_token(request),
            "username": enrollment["username"],
            "activation_url": enrollment["activation_url"],
            "activation_barcode": enrollment["activation_barcode"],
            "expires_at": expires_at.strftime("%d/%m/%Y %H:%M %Z"),
        },
    )


@app.post("/users/{username}/panel")
def set_panel_access(
    username: str,
    request: Request,
    csrf: str = Form(),
    enabled: bool = Form(),
    panel_password: str = Form(default=""),
):
    admin = require_admin(request)
    if isinstance(admin, RedirectResponse):
        return admin
    try:
        check_csrf(request, csrf)
        if enabled:
            readiness = call_helper(
                "duo-check", helper_payload(request, {"username": username})
            )["duo"]
            if readiness.get("result") != "auth" or not readiness.get("push_capable"):
                return redirect(
                    request,
                    f"Duo is not ready for {username}: "
                    f"{readiness.get('status', 'unknown status')}.",
                    "danger",
                    "users",
                )
    except HelperError as exc:
        return redirect(request, str(exc), "danger", "users")
    return mutate(
        request,
        csrf,
        "set-panel-access",
        {"username": username, "enabled": enabled, "panel_password": panel_password},
    )


@app.post("/users/{username}/delete")
def delete_user(username: str, request: Request, csrf: str = Form()):
    return mutate(request, csrf, "delete", {"username": username})


@app.post("/backups/{backup}/restore")
def restore_backup(backup: str, request: Request, csrf: str = Form()):
    return mutate(request, csrf, "restore", {"backup": backup}, anchor="system")


@app.get("/audit.csv")
def audit_csv(request: Request):
    admin = require_admin(request)
    if isinstance(admin, RedirectResponse):
        return admin
    events = call_helper("audit")["events"]
    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=["timestamp", "actor", "source_ip", "action", "target", "result", "detail"],
    )
    writer.writeheader()
    for event in events:
        writer.writerow(
            {
                key: f"'{value}" if str(value).startswith(("=", "+", "-", "@")) else value
                for key, value in event.items()
            }
        )
    return Response(
        output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=radius-user-admin-audit.csv"},
    )


@app.get("/diagnostics.txt")
def diagnostics(request: Request):
    admin = require_admin(request)
    if isinstance(admin, RedirectResponse):
        return admin
    data = call_helper("list")
    health = data["health"]
    certificate = health["certificate"]
    lines = [
        "RadiusPilot diagnostic",
        f"Generated: {datetime.now(UTC).isoformat(timespec='seconds')}",
        f"FreeRADIUS active: {health['active']}",
        f"FreeRADIUS configuration valid: {health['config_valid']}",
        f"Duo Authentication Proxy active: {health['duo_active']}",
        f"Nginx active: {health['nginx_active']}",
        f"Certificate valid: {certificate['valid']}",
        f"Certificate days remaining: {certificate['days_remaining']}",
        f"Disk free: {health['disk_free_mb']} MiB",
        f"Managed users: {len(data['users'])}",
        "Secrets and password hashes are intentionally omitted.",
    ]
    return PlainTextResponse(
        "\n".join(lines) + "\n",
        headers={"Content-Disposition": "attachment; filename=radius-user-admin-diagnostic.txt"},
    )
