# Cisco ISR + FreeRADIUS + Duo: example configuration

This is the minimal working configuration that RadiusPilot expects around it:
a Cisco ISR terminating AnyConnect over IKEv2, the Duo Authentication Proxy in
front of FreeRADIUS, and — optionally — the same chain protecting SSH logins to
the router itself. Replace the example addresses (`192.0.2.x`), names, secrets
and the trustpoint with your own. The RADIUS server host is called `radius01`
here, matching the rest of the documentation.

![Authentication flow: the AnyConnect client reaches the Cisco ISR over IKEv2, the ISR sends RADIUS to the Duo Authentication Proxy, the proxy validates the primary password against FreeRADIUS on 127.0.0.1:18120 and the second factor against the Duo cloud, and RadiusPilot maintains the generated authorize file](img/isr-freeradius-flow.svg)

The ISR never talks to FreeRADIUS directly: it sends every request to the Duo
Authentication Proxy, which first validates the password against FreeRADIUS and
only then triggers the Push.

## 1. Shared AAA and RADIUS plumbing on the ISR

```
aaa new-model
aaa group server radius DUO-RADIUS
 server name DUO

radius server DUO
 address ipv4 192.0.2.112 auth-port 1812 acct-port 1813
 timeout 120
 retransmit 1
 key YOUR-RADIUS-SHARED-SECRET

ip radius source-interface GigabitEthernet0/0/0
```

`timeout 120` and `retransmit 1` are not cosmetic. The Duo Push happens inside
the RADIUS exchange, so the router has to wait for a human to tap a phone. A
short timeout fails logins before the Push is answered, and retransmits send
duplicate Pushes.

## 2. AnyConnect over IKEv2 (FlexVPN)

```
aaa authentication login ANYCONNECT-DUO group DUO-RADIUS local
aaa authorization network ANYCONNECT-AUTHZ local

ip local pool ANYCONNECT-POOL 192.0.2.200 192.0.2.220
ip access-list standard ANYCONNECT-SPLIT
 permit 192.0.2.0 0.0.0.255

crypto ikev2 authorization policy ANYCONNECT-AUTHZ
 pool ANYCONNECT-POOL
 route set access-list ANYCONNECT-SPLIT

crypto ikev2 profile ANYCONNECT-EAP
 match identity remote key-id *$AnyConnectClient$*
 authentication local rsa-sig
 authentication remote anyconnect-eap aggregate
 pki trustpoint YOUR-TRUSTPOINT
 aaa authentication anyconnect-eap ANYCONNECT-DUO
 aaa authorization group anyconnect-eap list ANYCONNECT-AUTHZ ANYCONNECT-AUTHZ
 aaa authorization user anyconnect-eap cached
 virtual-template 100
 anyconnect profile ANYCONNECT-CLIENT
crypto ikev2 fragmentation mtu 1200

crypto ipsec transform-set DUO-IPSEC-TS esp-aes 256 esp-sha256-hmac
 mode tunnel
crypto ipsec profile ANYCONNECT-IPSEC
 set transform-set DUO-IPSEC-TS
 set ikev2-profile ANYCONNECT-EAP

interface Virtual-Template100 type tunnel
 ip unnumbered GigabitEthernet0/0/0
 ip mtu 1360
 tunnel mode ipsec ipv4
 tunnel protection ipsec profile ANYCONNECT-IPSEC

crypto vpn anyconnect profile ANYCONNECT-CLIENT bootflash:/acvpn.xml
```

Three lines deserve attention:

- `aaa authorization user anyconnect-eap cached` applies the per-user
  attributes that RadiusPilot returns in the Access-Accept. Without it the
  custom access policies (`ip:inacl#` and `ipsec:route-set` pairs) are silently
  ignored and every user gets the group policy.
- `aaa authentication ... group DUO-RADIUS local` keeps a local fallback so the
  VPN survives a RADIUS outage. Any local username you create for that purpose
  must be listed in `RADIUS_ADMIN_LOCAL_FALLBACK_USERS`, because a fallback
  login bypasses the downloaded ACL entirely.
- `anyconnect profile` pushes the client XML on every connection — but only
  over an already-established IKEv2 session. The very first connection needs
  the profile seeded on the client out of band (installer, MDM, or a copy into
  the Secure Client profile directory), because without a local profile the
  client attempts TLS instead of IKEv2 and never reaches the router.

## 3. SSH logins to the router with Duo (optional)

```
aaa authentication login default local
aaa authentication login SSH-DUO group DUO-RADIUS local

line vty 0 4
 login authentication SSH-DUO
 transport input ssh
```

Keep `default local` so the physical console always accepts the break-glass
account, and keep the `local` tail on the vty list. Test from a second SSH
session before closing the one you configured it from: a wrong list here locks
you out of your own router.

## 4. What to create in the Duo Admin Panel

None of the Duo credentials go into FreeRADIUS: FreeRADIUS only ever checks the
primary password. The keys live in the Authentication Proxy and in
RadiusPilot's enrollment file, and they come from **two separate applications**
you create after signing up at [duo.com](https://duo.com). Duo's free tier
covers up to ten users, which is what makes this whole setup attractive for a
small business — and everything RadiusPilot needs works on that tier. In
particular, the **Admin API application is not required**: it is a paid
feature, and RadiusPilot deliberately uses only the Auth API (user creation,
readiness checks and QR enrollments all go through Auth API endpoints).

**1. A RADIUS application for the Authentication Proxy.** In the Duo Admin
Panel go to *Applications → Protect an Application* and pick **RADIUS** (it
then appears in your application list as "RADIUS"). Duo shows three values —
*Integration key*, *Secret key* and *API hostname* — which map directly to
`ikey=`, `skey=` and `api_host=` in the `[radius_server_auto]` section of
`authproxy.cfg` below. While you are there, set the application's policy for
unknown users to **deny**: per-user "password only" exceptions are handled by
RadiusPilot's managed exemption block, never by loosening the Duo application
itself.

**2. An Auth API application for enrollment.** Protect a second application of
type **Auth API** (it appears in the list as "Partner Auth API"). Its three
values are what RadiusPilot stores in its root-only credential file, which must
never enter Git:

```json
// /etc/radius-user-admin/duo-enroll-api.json  (root:root, mode 0600)
{
  "ikey": "YOUR-AUTH-API-INTEGRATION-KEY",
  "skey": "YOUR-AUTH-API-SECRET-KEY",
  "api_host": "api-XXXXXXXX.duosecurity.com"
}
```

You do not have to write that file by hand: a signed-in panel administrator can
paste the three values under **System → Duo enrollment API** in the console.
They are validated against Duo before being stored and are never displayed
again afterwards.

Keep the two applications separate. The console uses the Auth API for
readiness checks, Push verification and QR enrollments; the proxy uses the
RADIUS application for logins. Reusing one set of keys for both jobs is
explicitly unsupported, and the proxy's RADIUS keys are deliberately not
editable from the console.

**3. Usernames must match exactly.** The username in FreeRADIUS, the one the
person types into AnyConnect and the one enrolled in Duo are the same string —
email-style names such as `user@example.com` included. RadiusPilot enforces
this by checking Duo readiness against the RADIUS username before it enables
Push for an account.

### From Duo sign-up to a working login

1. Create both applications above and note their keys.
2. Fill `[radius_server_auto]` in `authproxy.cfg` (next section) with the
   RADIUS application's keys, validate the proxy configuration, and restart it.
3. Enter the Auth API keys under **System → Duo enrollment API** in the
   console (or write `/etc/radius-user-admin/duo-enroll-api.json` by hand).
4. Create the VPN user in RadiusPilot and use **Enroll in Duo**: the console
   creates the Duo user through the Auth API and shows a QR activation valid
   for seven days. The person scans it with Duo Mobile.
5. Use **Check Duo readiness** from the user's row: it confirms enrollment and
   Push capability without sending a Push.
6. Connect with AnyConnect: password first, Push on the phone second. The
   *Recent VPN authentication* panel in the console shows both stages.

## 5. Duo Authentication Proxy (`authproxy.cfg`)

```ini
[main]
log_auth_events=true

[radius_client]
host=127.0.0.1
port=18120
secret=YOUR-FREERADIUS-SECRET
pass_through_attr_names=Cisco-AVPair

[radius_server_auto]
ikey=YOUR-INTEGRATION-KEY
skey=YOUR-SECRET-KEY
api_host=api-XXXXXXXX.duosecurity.com
radius_ip_1=192.0.2.1
radius_secret_1=YOUR-RADIUS-SHARED-SECRET
failmode=secure
client=radius_client
port=1812
```

`pass_through_attr_names=Cisco-AVPair` is the setting RadiusPilot's reconciler
checks before it allows custom access policies: without it the proxy strips the
downloaded ACL from the reply. `failmode=secure` fails closed when the Duo
cloud is unreachable; decide deliberately if you prefer `safe`. RadiusPilot
manages only its marked exemption block inside `[radius_server_auto]` and never
touches the rest of this file.

## 6. FreeRADIUS

FreeRADIUS only answers the proxy on loopback and reads the user file that
RadiusPilot generates. The relevant pieces:

```
# clients.conf — the proxy is the only client
client duo_authproxy_loopback {
    ipaddr = 127.0.0.1
    secret = YOUR-FREERADIUS-SECRET
}

# sites-enabled: listen on the alternate port the proxy targets
listen {
    type = auth
    ipaddr = 127.0.0.1
    port = 18120
}

# mods-enabled/files — point the files module at the managed directory
files {
    moddir = ${modconfdir}/${.:instance}
    filename = ${moddir}/authorize
}
```

The `authorize` file itself is generated by RadiusPilot (`root:freerad`, mode
`0640`) and stores MS-CHAPv2-compatible NT hashes, which is what the ISR's
AnyConnect-EAP authentication requires. Do not edit it by hand; set
`RADIUS_ADMIN_AUTHORIZE_PATH` if your files module uses a site-specific
directory.

## 7. Optional: live "online now" with RADIUS accounting

To show connected sessions in the console, have the gateway send RADIUS
accounting and let FreeRADIUS log it where RadiusPilot can read it.

On the ISR, add accounting to the AnyConnect profile's authorization and point
it at the same RADIUS group:

```
aaa accounting network ANYCONNECT-ACCT start-stop group DUO-RADIUS
aaa accounting update periodic 1

crypto ikev2 profile ANYCONNECT-EAP
 aaa accounting anyconnect-eap ANYCONNECT-ACCT
```

`aaa accounting update periodic <minutes>` is **required**, not optional. With
`start-stop` alone the gateway sends only a Start and a Stop, so a long-lived
session has no fresh accounting between them and ages out of the staleness
window (below) — the user connects fine but silently drops off "online now"
after `RADIUS_ADMIN_ACCT_STALE_SECONDS`. A periodic Interim-Update (every minute
here) keeps the session current and refreshes its data counters live. The
setting applies to sessions established after it is configured, so reconnect an
existing session to pick it up. The `radius server` block already sets
`acct-port 1813`. Accounting is best-effort and never blocks a login.

On `radius01`:

- Allow `1813/udp` from the gateway in the firewall (see `deploy/nftables.conf`).
- Install `deploy/freeradius-radius-pilot-detail.conf` as a FreeRADIUS `detail`
  module, enable it, and reference `radius_pilot_detail` in the site's
  `accounting {}` section. Install `deploy/radius-pilot-detail.logrotate` to
  keep the file bounded. Validate FreeRADIUS and restart it.

RadiusPilot reads the detail file and reconstructs current sessions: a session
is online while its latest accounting record is not a Stop and is newer than
`RADIUS_ADMIN_ACCT_STALE_SECONDS` (default 1800), so a lost Stop cannot pin a
user online forever. The dashboard then shows an "Online now" count, an Online
badge on connected users, and the assigned IP and duration in the user's row.

## 8. Optional: disconnect a session from the console (RADIUS CoA)

With accounting in place, the console can drop a live session on demand by
sending a RADIUS Change-of-Authorization Disconnect-Request to the gateway.
Enable the gateway to accept CoA from `radius01`:

```
aaa server radius dynamic-author
 client 192.0.2.10 server-key YOUR-COA-SHARED-SECRET
 auth-type any
 port 1700
```

Then set `RADIUS_ADMIN_COA_TARGET` (the gateway's `ip:1700`) and
`RADIUS_ADMIN_COA_SECRET` (the same key) in the environment file. RadiusPilot
sends the Disconnect-Request keyed on the session's assigned
`Framed-IP-Address`, which is what IOS XE matches for AnyConnect sessions. The
user can reconnect afterwards unless the account is also blocked. A "Disconnect"
button then appears on each online user.

Platform note: like the downloadable ACLs, CoA teardown must be validated on the
exact IOS XE release. On some FlexVPN/IKEv2 builds (observed on 17.12) the
gateway accepts the Disconnect-Request, or answers inconsistently, without
reliably tearing down the AnyConnect IKEv2 session. Where teardown is required
and the platform does not honour CoA, block the account instead — the reconnect
is then refused and the reconciler removes it from the generated file.

## 9. Prove it end to end

Follow the safe rollout checklist in the README before trusting custom access
policies: create a canary account with one narrow rule, connect with
AnyConnect, and verify on the router that the allowed destination works and a
denied one does not (`show crypto session detail` shows the session; the
downloaded ACL entries appear in the reply). A pushed route is not a security
boundary — only the ACL is.

## 10. Device administration: console and SSH with Duo Push

Console/VTY logins to the routers and switches themselves can authenticate
against the same accounts, with the same Duo Push. The pieces are deliberately
isolated from the VPN path; see
[docs/ports-and-services.md](ports-and-services.md) for how the ports fit
together. Roll it out in **two stages** — prove the RADIUS login and the local
fallback first, then add the Push — and pilot on one device before touching the
rest.

### Server side

1. **Mark the accounts.** In the console, grant *device admin* to each account
   that may log in to devices (the account needs an NT hash — new and reset
   passwords already do). RadiusPilot writes
   `/etc/freeradius/3.0/mods-config/files/device-admin/authorize` (NT hash plus
   `Service-Type` and `shell:priv-lvl=15`) on every change and reconcile.
   **Restart FreeRADIUS after changing who holds the role** — the `files`
   module caches the file.
2. **FreeRADIUS.** Install `deploy/freeradius-device-admin.conf` as
   `sites-available/device-admin`, enable it, and add its clients: the devices
   themselves for stage one, and the Duo proxy's addresses for stage two. It
   listens on **1814** and verifies the device's PAP login against the same NT
   hash MS-CHAPv2 uses for the VPN. `freeradius -C`, then restart.
3. **Duo proxy (stage two).** Add a second integration that fronts the virtual
   server with the Push — the `[radius_client1]` / `[radius_server_auto1]` pair
   shown in the README, listening on **1815**, with
   `pass_through_attr_names=Cisco-AVPair` (the privilege level rides that
   attribute) and `failmode=safe` (a Duo-cloud outage must not lock admins out
   of the network). Back up `authproxy.cfg` first; restart the proxy and check
   it still listens on both 1812 (VPN) and 1815.
4. **Firewall.** Allow `1815/udp` (and `1814/udp` while devices go direct in
   stage one) from each device's management address.

### Each device

Use **named** method lists — never edit the `default` lists or the VPN AAA —
keep `local` as the break-glass, and give the Push time:

```
radius server RADIUSPILOT-ADMIN
 address ipv4 <radius01> auth-port 1815 acct-port 0
 key <device-to-proxy secret>
 timeout 60
 retransmit 1
aaa group server radius RADIUSPILOT-ADMIN-RADIUS
 server name RADIUSPILOT-ADMIN
aaa authentication login RADIUSPILOT-ADMIN group RADIUSPILOT-ADMIN-RADIUS local
aaa authorization exec RADIUSPILOT-ADMIN group RADIUSPILOT-ADMIN-RADIUS local if-authenticated
line con 0
 login authentication RADIUSPILOT-ADMIN
 authorization exec RADIUSPILOT-ADMIN
line vty 0 15
 login authentication RADIUSPILOT-ADMIN
 authorization exec RADIUSPILOT-ADMIN
```

(For stage one, point `auth-port` at 1814 with the FreeRADIUS device client's
secret instead; everything else is identical.)

Apply it under a safety net, schedule the reload **on its own line first** —
pasting `reload in` together with configuration eats the confirmation prompt
and silently drops the rest:

1. `reload in 15` (confirm it), then paste the block.
2. Verify it landed: `show run | include RADIUSPILOT-ADMIN`.
3. Test without saving: `test aaa group RADIUSPILOT-ADMIN-RADIUS <user>
   <password> new-code` and a real SSH from a **new** session — enter the
   password, wait for the Push, approve, and check `show privilege` says 15.
4. Only then `reload cancel` and `write memory`. If anything went wrong, the
   device reverts to the saved configuration by itself, and the lines' `local`
   method keeps the break-glass account working throughout.

### What to expect

- A **reject never falls back to `local`** — only an unreachable RADIUS does.
  Wrong password means denied, as it should.
- An account that is not enrolled in Duo is denied by the Push stage; enroll it
  from the console first (or keep it on the stage-one port if it is an
  automation account that cannot Push).
- `timeout 60` is required: the IOS default of ~5 s expires long before a human
  can approve the Push.
- The Duo proxy's `authevents.log` records both stages — primary and Push — per
  login, and feeds the console's authentication history.
- RADIUS gives you login and privilege level. Per-command authorization and
  command accounting need TACACS+, which FreeRADIUS does not speak.
