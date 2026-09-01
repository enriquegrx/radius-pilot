from __future__ import annotations

import csv
import io
import ipaddress
import os
import secrets
import time
from collections import defaultdict, deque
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import quote
from zoneinfo import ZoneInfo

from fastapi import FastAPI, Form, Request
from fastapi.responses import PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .helper_client import HelperError, call_helper

BASE = Path(__file__).resolve().parent
SESSION_TTL = 30 * 60
LOGIN_WINDOW = 10 * 60
LOGIN_LIMIT = 5
LOGIN_LOCKOUT = 15 * 60
LOCAL_ZONE = ZoneInfo("Europe/Madrid")
LOGIN_ATTEMPTS: dict[str, deque[float]] = defaultdict(deque)
LOGIN_LOCKED_UNTIL: dict[str, float] = {}

app = FastAPI(title="Radius User Admin", docs_url=None, redoc_url=None)
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["radius.your-domain.com", "127.0.0.1", "localhost", "testserver"],
)
app.add_middleware(
    SessionMiddleware,
    secret_key=os.environ.get("RADIUS_ADMIN_SESSION_SECRET", secrets.token_hex(32)),
    https_only=os.environ.get("RADIUS_ADMIN_SECURE_COOKIE", "1") == "1",
    same_site="strict",
    max_age=SESSION_TTL,
)
app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")
templates = Jinja2Templates(directory=BASE / "templates")


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
    if (
        not admin
        or not isinstance(last_seen, (int, float))
        or time.time() - last_seen > SESSION_TTL
    ):
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


def redirect(message: str, level: str = "success", anchor: str = "") -> RedirectResponse:
    suffix = f"#{anchor}" if anchor else ""
    return RedirectResponse(
        f"/?message={quote(message)}&level={quote(level)}{suffix}", status_code=303
    )


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


@app.get("/login")
def login_page(request: Request, error: str = ""):
    if current_admin(request):
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse(
        request,
        "login.html",
        {"csrf": csrf_token(request), "error": error},
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
        return RedirectResponse(f"/login?error={quote(str(exc))}", status_code=303)
    ip = source_ip(request)
    current = time.time()
    if LOGIN_LOCKED_UNTIL.get(ip, 0) > current:
        return RedirectResponse(
            "/login?error=Too%20many%20attempts.%20Try%20again%20later.", status_code=303
        )
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
        return RedirectResponse("/login?error=Invalid%20credentials.", status_code=303)
    LOGIN_ATTEMPTS.pop(ip, None)
    LOGIN_LOCKED_UNTIL.pop(ip, None)
    request.session.clear()
    request.session.update(
        {"admin": username.strip().lower(), "last_seen": current, "csrf": secrets.token_urlsafe(32)}
    )
    return RedirectResponse("/", status_code=303)


@app.post("/logout")
def logout(request: Request, csrf: str = Form()):
    try:
        check_csrf(request, csrf)
    finally:
        request.session.clear()
    return RedirectResponse("/login", status_code=303)


@app.get("/")
def index(request: Request, message: str = "", level: str = "success"):
    admin = require_admin(request)
    if isinstance(admin, RedirectResponse):
        return admin
    error = ""
    try:
        data = call_helper("list")
        activity = call_helper("audit")
        backups = call_helper("backups")["backups"]
        users = data["users"]
        health = data["health"]
    except HelperError as exc:
        users, backups, error = [], [], str(exc)
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
            "message": message,
            "level": level if level in {"success", "danger", "warning"} else "success",
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
        },
    )


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


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
        return redirect("Change applied and authentication services validated.", anchor=anchor)
    except HelperError as exc:
        return redirect(str(exc), "danger", anchor)


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
):
    try:
        admin = require_admin(request)
        if isinstance(admin, RedirectResponse):
            return admin
        check_csrf(request, csrf)
        account_expiry = utc_form_time(expires_at)
        bypass_expiry = utc_form_time(duo_bypass_until)
    except HelperError as exc:
        return redirect(str(exc), "danger", "users")
    if duo_required or panel_access:
        try:
            readiness = call_helper("duo-check", {"username": username})["duo"]
            if readiness.get("result") != "auth" or not readiness.get("push_capable"):
                return redirect(
                    f"Duo is not ready for {username}: "
                    f"{readiness.get('status', 'unknown status')}.",
                    "danger",
                    "users",
                )
        except HelperError as exc:
            return redirect(str(exc), "danger", "users")
    return mutate(
        request,
        csrf,
        "create",
        {
            "username": username,
            "password": password,
            "duo_required": duo_required,
            "expires_at": account_expiry,
            "duo_bypass_until": bypass_expiry,
            "duo_bypass_reason": duo_bypass_reason,
            "panel_access": panel_access,
            "panel_password": panel_password,
        },
    )


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
            readiness = call_helper("duo-check", {"username": new_username})["duo"]
            if readiness.get("result") != "auth" or not readiness.get("push_capable"):
                return redirect(
                    f"Duo is not ready for {new_username}: "
                    f"{readiness.get('status', 'unknown status')}.",
                    "danger",
                    "users",
                )
    except (HelperError, StopIteration) as exc:
        return redirect(str(exc) or "User not found.", "danger", "users")
    return mutate(request, csrf, "rename", {"username": username, "new_username": new_username})


@app.post("/users/{username}/password")
def reset_password(
    username: str,
    request: Request,
    csrf: str = Form(),
    password: str = Form(),
):
    return mutate(request, csrf, "reset-password", {"username": username, "password": password})


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
            readiness = call_helper("duo-check", {"username": username})["duo"]
            if readiness.get("result") != "auth" or not readiness.get("push_capable"):
                return redirect(
                    f"Duo is not ready for {username}: "
                    f"{readiness.get('status', 'unknown status')}.",
                    "danger",
                    "users",
                )
        bypass_expiry = utc_form_time(duo_bypass_until)
    except HelperError as exc:
        return redirect(str(exc), "danger", "users")
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
        return redirect(str(exc), "danger", "users")
    return mutate(request, csrf, "set-expiry", {"username": username, "expires_at": expiry})


@app.post("/users/{username}/duo-check")
def check_duo(username: str, request: Request, csrf: str = Form()):
    admin = require_admin(request)
    if isinstance(admin, RedirectResponse):
        return admin
    try:
        check_csrf(request, csrf)
        duo = call_helper("duo-check", {"username": username})["duo"]
        capability = "Push ready" if duo["push_capable"] else "no Push-capable device"
        return redirect(
            f"Duo {duo['status']}; {duo['device_count']} device(s), {capability}.",
            "success" if duo["result"] == "auth" and duo["push_capable"] else "warning",
            "users",
        )
    except HelperError as exc:
        return redirect(str(exc), "danger", "users")


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
            readiness = call_helper("duo-check", {"username": username})["duo"]
            if readiness.get("result") != "auth" or not readiness.get("push_capable"):
                return redirect(
                    f"Duo is not ready for {username}: "
                    f"{readiness.get('status', 'unknown status')}.",
                    "danger",
                    "users",
                )
    except HelperError as exc:
        return redirect(str(exc), "danger", "users")
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
        "Radius User Admin diagnostic",
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
