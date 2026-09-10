# Architecture

## Recommended zero-additional-license design

```text
Internet
   |
FortiGate / reverse proxy
   |
===================== DMZ =====================
   |
JcfSspr.Portal (DMZ instance)
- no AD credential
- no SQL credential
- no LDAP route
- no personnel DB route
   |
   | HTTPS 443 + mTLS
   | firewall: portal IP -> broker IP only
   v
=================== INTERNAL ==================
JcfSspr.Broker
- runs as gMSA/service identity
- validates possession factor
- authoritative member/account mapping
- durable throttle/audit store
   |                   |
   | TLS + Integrated  | validated LDAPS 636
   v                   v
Member/Security SQL    Member OU in AD

JcfSspr.Portal (internal instance) ----mTLS----^
```

The same `JcfSspr.Portal` binary can be installed twice: one DMZ-facing instance and one internal instance. Each instance gets a different client certificate so either path can be revoked independently.

## Trust boundaries

The portal is considered compromiseable. A portal compromise must not disclose a reusable AD/SQL password or allow arbitrary LDAP/SQL access. The portal can submit only reset requests to the broker.

The broker is a Tier-1 security component and must remain internal. It is the only application process granted password-reset rights. Its gMSA should be delegated `Reset password` only on the member OU, denied interactive logon, and excluded from privileged OUs.

## Identity and reset flow

1. Member supplies regulation/computer number plus existing personnel attributes to locate the member.
2. Broker performs a generic match without revealing which field failed.
3. Broker requires a TOTP code from an authenticator enrolled previously through the internal enrollment page. A single-use recovery code is accepted as the emergency self-service possession factor.
4. Broker issues a five-minute, one-use reset transaction bound to the portal certificate and client address. The password is submitted only in the second request.
5. Broker obtains `AD Object GUID`, `AD Account Name`, and notification address from the authoritative member view. The client never supplies the reset target.
6. Broker validates password policy and rejects privileged/protected accounts.
7. Broker locates the AD object by GUID inside the member OU, confirms the returned `sAMAccountName` matches the authoritative value, and writes `unicodePwd` over certificate-validated LDAPS.
8. Broker records the event and sends a post-reset notification when the configured existing SMTP relay is available.

## Enrollment

`/enroll` exists only on the internal broker and requires Windows/Negotiate authentication. The authenticated Windows account must map exactly to the authoritative `AD Account Name` in the member view. The user scans a QR code, proves one TOTP code, and receives one-time recovery codes.

A person who is not enrolled cannot self-enroll after forgetting the password. Existing ICTD/service-desk identity procedures remain the fallback.
