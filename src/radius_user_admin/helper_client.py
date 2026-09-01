from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any


class HelperError(RuntimeError):
    """A safe error returned by the privileged helper."""


def helper_command() -> list[str]:
    configured = os.environ.get("RADIUS_ADMIN_HELPER")
    if configured:
        return [str(Path(configured))]
    return ["/usr/bin/sudo", "-n", "/usr/local/sbin/radius-user-admin-helper"]


def call_helper(operation: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    request = json.dumps(payload or {}, ensure_ascii=False).encode()
    try:
        result = subprocess.run(
            [*helper_command(), operation],
            input=request,
            capture_output=True,
            check=False,
            timeout=75 if operation == "authenticate-admin" else 30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise HelperError("The FreeRADIUS management service is unavailable.") from exc

    try:
        response = json.loads(result.stdout.decode() or "{}")
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HelperError("The FreeRADIUS helper returned an invalid response.") from exc

    if result.returncode or not response.get("ok", False):
        message = response.get("error", "The requested change could not be applied.")
        raise HelperError(str(message))
    return response
