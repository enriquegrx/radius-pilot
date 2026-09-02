# Ports and services map

What listens where, why, and how the RADIUS flows fit together. Keep this
current when a port or integration changes.

## `radius01` (172.26.200.112)

| Port | Proto | Service | Bound to | From | Purpose |
|------|-------|---------|----------|------|---------|
| 22 | tcp | sshd | all | admin set | Server administration |
| 443 | tcp | Nginx | all | web set | HTTPS console (RadiusPilot) |
| 8080 | tcp | FastAPI (uvicorn) | 127.0.0.1 | Nginx only | Console backend (loopback) |
| 1812 | udp | **Duo Auth Proxy** | all | gateway 172.26.200.1 | **VPN** AnyConnect auth → Duo Push |
| 1813 | udp | **FreeRADIUS** | 172.26.200.112 | gateway 172.26.200.1 | **RADIUS accounting** (feeds "online now" / map / CoA) |
| 1814 | udp | **FreeRADIUS** `device-admin` vserver | 172.26.200.112 | gateway (pass 1) / Duo proxy (pass 2) | **Device CLI auth** (router/switch SSH/console) → priv 15 |
| 1815 | udp | **Duo Auth Proxy** (device-admin) | all | gateway 172.26.200.1 | **Device CLI auth WITH Duo Push** (pass 2) |
| 18120 | udp | **FreeRADIUS** `bios-primary` | 127.0.0.1 | Duo proxy only | VPN primary-auth backend (behind the Duo proxy) |

Firewall (`/etc/nftables.conf`): default-drop; 22 from the admin set, 443 from
the web set, and 1812/1813/1814/1815 udp from the gateway 172.26.200.1.

## Cisco hub router (BIOS, 172.26.200.1, RADIUS source = Vlan200)

| `radius server` | Target | Method lists | Purpose |
|-----------------|--------|--------------|---------|
| `BIOS-DUO` | radius01:1812 | `BIOS-ANYCONNECT-DUO` | VPN auth via the Duo proxy |
| `BIOS-ACCT` | radius01:1813 (acct) | accounting | VPN accounting |
| `BIOS-NETADMIN` | radius01:**1814** (pass 1) → **1815** (pass 2) | `BIOS-NETADMIN` login + exec authz, on con 0 + vty | Device CLI login, `local` break-glass |

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
| Router ↔ Duo proxy (VPN, 1812) | router `radius server BIOS-DUO key`; Duo proxy `[radius_server_auto] radius_secret_1` |
| Router ↔ FreeRADIUS (acct, 1813) | router `radius server BIOS-ACCT`; FreeRADIUS `bios_acct_clients` |
| Router ↔ FreeRADIUS (device-admin direct, 1814, pass 1) | router `radius server BIOS-NETADMIN key`; FreeRADIUS `device_admin_clients` (client 172.26.200.1) |
| Router ↔ Duo proxy (device-admin, 1815, pass 2) | router `radius server BIOS-NETADMIN key`; Duo proxy `[radius_server_auto1] radius_secret_1` |
| Duo proxy ↔ FreeRADIUS (device-admin backend, 1814, pass 2) | Duo proxy `[radius_client1] secret`; FreeRADIUS `device_admin_clients` (client 172.26.200.112) |
| Duo proxy ↔ FreeRADIUS (VPN backend, 18120) | Duo proxy `[radius_client] secret`; FreeRADIUS `bios_loopback_clients` |
| Router CoA (dynamic-author) | router `aaa server radius dynamic-author`; RadiusPilot `RADIUS_ADMIN_COA_SECRET` |

Duo cloud API host for Push: `api-c6cca022.duosecurity.com` (Internet, outbound
from the Duo proxy only).
