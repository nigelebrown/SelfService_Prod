# Architecture

## Trust boundaries

```text
Internet / approved internal kiosks
              |
           HTTPS 443
              v
====================== DMZ ======================
IdentityRecovery.DmzPortal
- separate deployment package; not domain joined
- no AD/LDAP, HR/SQL, SMB, RDP or WinRM route
- no reusable internal credentials or credential database
- optional hardened kiosk mode
              |
              | HTTPS 443 + mandatory allow-listed mTLS client certificate
              | request-ID + timestamp anti-replay
              v
================ INTERNAL APP ZONE ==============
IdentityRecovery.InternalService
- Windows/gMSA service identity
- HR identity resolution and photo retrieval
- PIN verifier + protected TOTP/recovery credentials
- AD objectGUID binding, reset and provisioning
- AD-group-SID RBAC administration + local break-glass path
- review queue, append-only audit, security alerts, retention/readiness workers
              |
        +-----+---------------------+
        |                           |
 TLS + integrated auth       validated LDAPS 636
        v                           v
 HR/personnel source         Active Directory DS
 Security SQL store          Windows Server 2016-2022 target
```

The DMZ package is treated as compromiseable. Compromise must not provide a network path or reusable credential to HR, SQL or AD. The internal API is the only application bridge.

## Identity lifecycle

First-time self-registration uses a secure PIN plus configured HR corroboration, then profile/photo confirmation and mandatory TOTP enrollment before password completion. Admin-assisted registration is available internally: a Helpdesk-authorized administrator verifies the member in person against the HR profile, records a support reference, and the member privately chooses their own PIN; only its verifier is stored.

Routine recovery prefers TOTP. The internal service creates a five-minute, one-use transaction bound to source IP, mTLS client identity, HR subject, AD objectGUID and account name. The browser cannot select an AD object.

## AD provisioning

Before creation the service searches HR-linked identifiers in AD. A unique authoritative `employeeID` match is reused; ambiguity or collision fails closed to the review queue. New accounts are created disabled in a configured staging OU and enabled only after required TOTP enrollment and successful password setting.

Self-service provisioning requires both a positive profile allow-list and a positive group allow-list. All configured profile groups are recursively checked through AD for transitive ancestry into denied privileged groups. If validation cannot be completed, group provisioning fails closed. Password reset separately rejects denied account names, `adminCount=1`, direct denied-group membership, and transitive denied-group membership using the AD LDAP matching-rule-in-chain OID `1.2.840.113556.1.4.1941`.

## Administrative RBAC

AD groups provide automatic application authorization through immutable SIDs:

- Platform Admin — full platform administration and break-glass custody.
- Helpdesk — member support and assisted registration.
- Provisioning Admin — approved OU/group profile changes and review queue.
- Security Admin — self-service security state and security-response controls.
- Auditor — read-only audit search.

The local break-glass administrator uses password + TOTP and exists only in the Internal Service security store. It is for emergency internal access, not normal operation.

## Audit and operational security

`IdentityAudit` is append-only through both an EF interceptor and a SQL `INSTEAD OF UPDATE, DELETE` trigger. Critical events are structured logs suitable for the existing SIEM/logging pipeline and can also use the configured security notification channel. A retention worker deletes only transient operational state, not audit history.

Both tiers expose liveness/readiness endpoints. Data Protection key rings can be placed on recoverable shared storage and certificate-protected for HA/DR.
