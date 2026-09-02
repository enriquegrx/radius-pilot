# Ports and services map

What listens where, why, and how the RADIUS flows fit together. Keep this
current when a port or integration changes.
Addresses and names here are RFC 5737-style examples — substitute your own;
the live values stay on the hosts, never in git.

## `radius01` (192.0.2.112)

| Port | Proto | Service | Bound to | From | Purpose |
|------|-------|---------|----------|------|---------|
| 22 | tcp | sshd | all | admin set | Server administration |
| 443 | tcp | Nginx | all | web set | HTTPS console (RadiusPilot) |
| 8080 | tcp | FastAPI (uvicorn) | 127.0.0.1 | Nginx only | Console backend (loopback) |
| 1812 | udp | **Duo Auth Proxy** | all | gateway 192.0.2.1 | **VPN** AnyConnect auth → Duo Push |
| 1813 | udp | **FreeRADIUS** | 192.0.2.112 | gateway 192.0.2.1 | **RADIUS accounting** (feeds "online now" / map / CoA) |
| 1814 | udp | **FreeRADIUS** `device-admin` vserver | 192.0.2.112 | gateway (pass 1) / Duo proxy (pass 2) | **Device CLI auth** (router/switch SSH/console) → priv 15 |
| 1815 | udp | **Duo Auth Proxy** (device-admin) | all | gateway 192.0.2.1 | **Device CLI auth WITH Duo Push** (pass 2) |
| 18120 | udp | **FreeRADIUS** `primary` site | 127.0.0.1 | Duo proxy only | VPN primary-auth backend (behind the Duo proxy) |

Firewall (`/etc/nftables.conf`): default-drop; 22 from the admin set, 443 from
the web set, and 1812/1813/1814/1815 udp from the gateway 192.0.2.1.

## Cisco gateway router (192.0.2.1; RADIUS source-interface = its management SVI)

| `radius server` | Target | Method lists | Purpose |
|-----------------|--------|--------------|---------|
| `VPN-DUO` | radius01:1812 | `ANYCONNECT-DUO` | VPN auth via the Duo proxy |
| `VPN-ACCT` | radius01:1813 (acct) | accounting | VPN accounting |
| `RADIUSPILOT-ADMIN` | radius01:**1814** (pass 1) → **1815** (pass 2) | `RADIUSPILOT-ADMIN` login + exec authz, on con 0 + vty | Device CLI login, `local` break-glass |

## Authentication flows

**VPN (AnyConnect):** client → router → Duo proxy `:1812` → FreeRADIUS `:18120`
(primary, MS-CHAP against NT hash) → Duo Push → `Access-Accept` (+ dACL for
custom-access users). Accounting streams to FreeRADIUS `:1813`.

**Device CLI — pass 1 (no Duo, password only):** SSH/console → router →
FreeRADIUS `device-admin` `:1814` (PAP against NT hash) → reply
`Service-Type=NAS-Prompt-User` + `Cisco-AVPair=shell:priv-lvl=15`. `local`
fallback on the lines if RADIUS is unreachable.

**Device CLI — pass 2 (with Duo Push):** SSH/console → router → Duo proxy
`:1815` → primary against FreeRADIUS `device-admin` `:1814` → Duo Push → priv 15.
The Duo integration forwards `Cisco-AVPair` so the shell privilege reaches the
router; `failmode=safe` so a Duo-cloud outage does not lock admins out (the
line `local` still covers a full RADIUS outage).

## Shared secrets (values live only on the hosts, never in git)

| Between | Where configured |
|---------|------------------|
| Router ↔ Duo proxy (VPN, 1812) | router `radius server VPN-DUO key`; Duo proxy `[radius_server_auto] radius_secret_1` |
| Router ↔ FreeRADIUS (acct, 1813) | router `radius server VPN-ACCT`; FreeRADIUS `acct_clients` |
| Router ↔ FreeRADIUS (device-admin direct, 1814, pass 1) | router `radius server RADIUSPILOT-ADMIN key`; FreeRADIUS `device_admin_clients` (client 192.0.2.1) |
| Router ↔ Duo proxy (device-admin, 1815, pass 2) | router `radius server RADIUSPILOT-ADMIN key`; Duo proxy `[radius_server_auto1] radius_secret_1` |
| Duo proxy ↔ FreeRADIUS (device-admin backend, 1814, pass 2) | Duo proxy `[radius_client1] secret`; FreeRADIUS `device_admin_clients` (client 192.0.2.112) |
| Duo proxy ↔ FreeRADIUS (VPN backend, 18120) | Duo proxy `[radius_client] secret`; FreeRADIUS `loopback_clients` |
| Router CoA (dynamic-author) | router `aaa server radius dynamic-author`; RadiusPilot `RADIUS_ADMIN_COA_SECRET` |

Duo cloud API host for Push: `api-XXXXXXXX.duosecurity.com` (Internet, outbound
from the Duo proxy only).
