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

## 4. Duo Authentication Proxy (`authproxy.cfg`)

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

## 5. FreeRADIUS

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

## 6. Prove it end to end

Follow the safe rollout checklist in the README before trusting custom access
policies: create a canary account with one narrow rule, connect with
AnyConnect, and verify on the router that the allowed destination works and a
denied one does not (`show crypto session detail` shows the session; the
downloaded ACL entries appear in the reply). A pushed route is not a security
boundary — only the ACL is.
