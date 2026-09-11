# Architecture

## Hard trust separation

```text
Internet / internal kiosk users
           |
      HTTPS 443
           v
====================== DMZ ======================
IdentityRecovery.DmzPortal
- independent deployment package
- not domain joined
- no AD/LDAP route
- no HR/SQL route
- no service-account credentials
- no PIN/TOTP database
           |
           | HTTPS 443 + mandatory mTLS
           | request ID + timestamp replay defense
           | firewall: exact portal IP -> exact service IP only
           v
================ INTERNAL APP ZONE ==============
IdentityRecovery.InternalService
- independent deployment package
- Windows/gMSA service identity
- Windows-authenticated admin console
- HR identity resolution and employee photo retrieval
- PIN verifier and TOTP/recovery credential store
- duplicate-safe AD identity linking/provisioning
- reset transactions, throttling, audit and review queue
           |
       +---+-------------------+
       |                       |
 TLS + integrated auth     validated LDAPS 636
       |                       |
       v                       v
 HR/personnel source      Active Directory DS
 Security SQL store       2016-2022 target
```

The DMZ package is considered compromiseable. Compromise must not reveal an AD/SQL service password or give the host a network route to the HR database or domain controllers. The only southbound application path is the constrained identity API over mTLS.

## Identity lifecycle

### First-time self-registration

1. User supplies an identifier (employee/computer/regulation number, username, or email as configured) plus the secure PIN.
2. Before a TOTP enrollment exists, the service also requires at least two matching HR corroboration attributes by default (for example TRN, DOB, middle name). These attributes are not authenticators.
3. Internal service validates the PIN verifier and HR identity. The DMZ receives no profile before authentication succeeds.
4. Internal service searches AD. A single authoritative existing employee-ID match is linked. Any ambiguity/collision creates an admin-review case and stops.
5. If no account exists and the provisioning policy permits it, a disabled account is created in the configured staging OU with only approved baseline groups.
6. The authenticated user sees the HR photo/profile and explicitly confirms it.
7. User enrolls a standards-based TOTP authenticator and proves the first code. Recovery codes are generated once and stored only as hashes.
8. User sets the directory password. Only after this succeeds is a newly provisioned account enabled.

### Routine recovery

1. User identifies the account and supplies a current TOTP code (preferred) or secure PIN.
2. Internal service authenticates the factor, then releases the HR profile/photo for confirmation.
3. A cryptographically random five-minute reset transaction is created, bound to source IP, mTLS client identity, HR subject, AD ObjectGUID and AD account.
4. The new password is submitted in a separate request and written to that exact AD object over validated LDAPS.
5. The transaction becomes unusable and the action is audited/optionally notified.

## Administration

The administration console exists only in the internal package. Windows/Negotiate authentication plus an allow-listed AD group SID is required. Administrators can issue one-time-display PINs, unlock PIN verification, revoke TOTP enrollment, enable/disable self-service, and apply configured OU/group profiles. They cannot retrieve PIN verifiers as PINs, TOTP secrets, passwords, or used recovery codes.

Provisioning profiles form an authorization boundary. Privileged groups are blocked globally. The profile engine reconciles only groups declared in platform profiles and never removes unrelated group memberships.
