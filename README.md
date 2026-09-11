# Identity Recovery & Self-Service Platform

This repository contains two independently deployable security packages plus a shared code library:

- **IdentityRecovery.DmzPortal** — the public/kiosk-facing presentation package. It is intentionally unprivileged, is not domain joined, stores no HR/AD/SQL credentials, and has no direct route to HR, SQL, LDAP, SMB, RDP, or WinRM.
- **IdentityRecovery.InternalService** — the internal identity authority and administration package. It performs HR identity resolution, secure PIN/TOTP validation, duplicate-safe AD resolution/provisioning, password reset, provisioning-policy enforcement, audit, and administrator support functions.
- **IdentityRecovery.Core** — shared contracts and cryptographic/security primitives.

The source directories retain their original internal namespace names for code continuity, but published assembly/product names are generic and the platform is not organization-branded.

## Security model

The DMZ portal can communicate only with the Internal Identity Service over HTTPS 443 using an allow-listed mutual-TLS client certificate. Every sensitive API request also carries a unique request ID and timestamp; the internal service rejects replayed or stale requests.

The Internal Identity Service uses Windows integrated authentication/gMSA for SQL and Active Directory operations. SQL certificate validation is mandatory and AD changes use validated LDAPS. No reusable AD or SQL password belongs in source or application configuration.

Static HR attributes resolve and corroborate a claimed identity but do not by themselves authorize registration or reset. Routine authentication uses a standards-based TOTP authenticator. A secure PIN can bootstrap/recover access; locally stored PINs are represented only by PBKDF2-HMAC-SHA256 verifiers using unique salts plus a separate server-side pepper. Three failed PIN attempts lock the PIN method without disabling an already-enrolled authenticator.

An HR profile/photo is released only after successful authentication. The browser never chooses the AD object to reset. The internal service binds the employee's immutable HR subject ID to the exact AD `objectGUID` and account name.

## AD provisioning

Before creating an account, the service searches AD for employee-ID and email/UPN/proxy-address matches. A unique employee-ID match is linked; any conflicting or ambiguous match stops automation and creates an administrator-review case. A new account is created **disabled** in a configured staging OU, receives only allow-listed baseline groups, and is enabled only after the member has completed required authenticator enrollment and successfully set a password.

Provisioning profiles configure target OUs and platform-managed groups. Self-service users may select only profiles explicitly marked `UserSelectable`; privileged groups are hard-blocked. Internal administrators can apply approved profiles, and switching profiles reconciles only groups managed by this platform so unrelated access is not disturbed.

## Administrator support

The internal administration console uses Windows authentication and a dedicated AD group-SID allow-list. Authorized staff can search an employee, inspect HR/AD linkage and recovery status, issue or replace a secure PIN (shown once only), unlock the PIN method, revoke authenticator enrollment, enable/disable self-service, and apply approved provisioning profiles. Administrative actions are audited; PINs, TOTP secrets, passwords, and stored recovery-code values are never retrievable.

## Quality and security gates

CI requires:

1. plaintext-secret scan;
2. architecture regression scan (including no DMZ LDAP/SQL code and no certificate-validation bypass);
3. .NET 10 Release build with warnings treated as errors and current analyzers;
4. unit/security tests;
5. vulnerable NuGet dependency reporting.

Read `docs/ARCHITECTURE.md`, `docs/DEPLOYMENT.md`, `docs/HR-INTEGRATION.md`, and `docs/SECURITY-TEST-PLAN.md` before deployment. A production release additionally requires an isolated HR/AD end-to-end test and network/security validation.
