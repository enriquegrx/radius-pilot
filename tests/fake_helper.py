#!/usr/bin/env python3
import json
import sys

_payload = json.load(sys.stdin)
if sys.argv[1] == "list":
    print(json.dumps({"ok": True, "users": [], "health": {"active": True, "config_valid": True}}))
else:
    print(json.dumps({"ok": True}))
