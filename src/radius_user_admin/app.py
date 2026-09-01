from __future__ import annotations

import os
import secrets
from pathlib import Path
from urllib.parse import quote

from fastapi import FastAPI, Form, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .helper_client import HelperError, call_helper

BASE = Path(__file__).resolve().parent
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
)
app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")
templates = Jinja2Templates(directory=BASE / "templates")


def csrf_token(request: Request) -> str:
    token = request.session.get("csrf")
    if not token:
        token = secrets.token_urlsafe(32)
        request.session["csrf"] = token
    return token


def redirect(message: str, level: str = "success") -> RedirectResponse:
    return RedirectResponse(f"/?message={quote(message)}&level={quote(level)}", status_code=303)


def check_csrf(request: Request, token: str) -> None:
    expected = request.session.get("csrf", "")
    if not expected or not secrets.compare_digest(expected, token):
        raise HelperError("The form expired. Refresh the page and try again.")


@app.get("/")
def index(request: Request, message: str = "", level: str = "success"):
    try:
        data = call_helper("list")
        users = data["users"]
        health = data["health"]
        error = ""
    except HelperError as exc:
        users, health, error = (
            [],
            {"active": False, "config_valid": False, "duo_active": False},
            str(exc),
        )
    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "users": users,
            "health": health,
            "message": message,
            "level": level if level in {"success", "danger", "warning"} else "success",
            "error": error,
            "csrf": csrf_token(request),
            "enabled_count": sum(user["enabled"] for user in users),
            "blocked_count": sum(not user["enabled"] for user in users),
        },
    )


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


def mutate(request: Request, token: str, operation: str, payload: dict[str, object]):
    try:
        check_csrf(request, token)
        call_helper(operation, payload)
        return redirect("Change applied and authentication services validated.")
    except HelperError as exc:
        return redirect(str(exc), "danger")


@app.post("/users")
def create_user(
    request: Request,
    csrf: str = Form(),
    username: str = Form(),
    password: str = Form(),
    duo_required: bool = Form(),
):
    return mutate(
        request,
        csrf,
        "create",
        {
            "username": username,
            "password": password,
            "duo_required": duo_required,
        },
    )


@app.post("/users/{username}/rename")
def rename_user(
    username: str,
    request: Request,
    csrf: str = Form(),
    new_username: str = Form(),
):
    return mutate(
        request,
        csrf,
        "rename",
        {"username": username, "new_username": new_username},
    )


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
    action = "unblocked" if enabled else "blocked"
    response = mutate(request, csrf, "set-enabled", {"username": username, "enabled": enabled})
    if response.headers.get("location", "").startswith("/?message=Change"):
        return redirect(f"User {action}; FreeRADIUS validated.")
    return response


@app.post("/users/{username}/duo")
def set_duo(
    username: str,
    request: Request,
    csrf: str = Form(),
    duo_required: bool = Form(),
):
    return mutate(
        request,
        csrf,
        "set-duo",
        {"username": username, "duo_required": duo_required},
    )


@app.post("/users/{username}/delete")
def delete_user(username: str, request: Request, csrf: str = Form()):
    return mutate(request, csrf, "delete", {"username": username})
