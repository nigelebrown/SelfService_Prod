# Identity Recovery & Self-Service Platform

This repository contains two independently deployable packages plus a shared security library:

- **IdentityRecovery.DmzPortal** — public/kiosk-facing presentation tier. It is not domain joined, contains no AD/HR/SQL credentials or credential stores, and its only southbound path is mTLS HTTPS to the Internal Identity Service.
- **IdentityRecovery.InternalService** — internal identity authority, HR integration, PIN/TOTP verification, AD reset/provisioning, administration, audit, security alerting and review workflows.
- **IdentityRecovery.Core** — shared contracts and cryptographic/security primitives.

## Identity and registration

Static HR attributes resolve/corroborate an identity but are not authenticators. TOTP is the preferred routine factor. A secure PIN is the bootstrap/fallback factor and is stored only as a salted/peppered PBKDF2-HMAC-SHA256 verifier. Three failed PIN attempts lock the PIN method while an already-enrolled authenticator remains usable.

For **admin-assisted registration**, authorized helpdesk staff first locate the HR record and verify the member against the HR photo/profile. The member then privately enters and confirms their own 8–12 digit PIN in masked fields. The PIN is immediately converted to its verifier, is never displayed back or logged, and the support reference is audited. The member then uses that PIN through the normal portal to bootstrap TOTP enrollment.

## AD provisioning safeguards

The internal service binds the immutable HR subject ID to the exact AD `objectGUID`. Existing identities are reused only when uniquely authoritative; collisions and ambiguity fail closed into an administrator review queue. New accounts are created disabled in a staging OU and are enabled only after required authenticator enrollment and successful password set.

Self-service profiles and groups use **positive allow-lists**, not only deny-lists. Configured groups are repeatedly checked through AD for nested/transitive ancestry to blocked privileged groups; failed or stale validation fails closed. Direct privileged groups remain blocked as defense in depth.

## Administration and RBAC

Normal administration uses Windows/AD authentication. Authorization is inherited automatically from configured AD security-group SIDs, with separate roles for platform administrators, helpdesk, provisioning administrators, security administrators and auditors. A local password+TOTP break-glass administrator exists only for emergency internal access and cannot create/rotate itself.

The admin package includes member support, assisted registration, self-service security controls, approved OU/group provisioning, a conflict/review queue, audit search and platform-only break-glass management. Sensitive support actions require a ticket/change/reference value and are audited.

## Operational hardening

The security database enforces application- and SQL-level append-only audit behavior. Critical security events can be forwarded through the configured notification channel and are always emitted as structured application logs for SIEM collection. Transient replay/reset/throttle/recovery state has automated retention cleanup; audits are not automatically deleted.

Both packages expose liveness/readiness endpoints. The internal readiness check verifies the security store, HR source, validated LDAPS and Data Protection key path. Data Protection key rings can be stored on protected shared storage and encrypted with a certificate to support HA/DR. The DMZ portal supports the same persistent/certificate-protected key model for multi-node TempData continuity.

Optional kiosk mode provides short idle timeout, automatic recovery-session reset, browser cache/storage clearing, no-store headers and back-forward-cache protection. OS/browser kiosk lockdown still belongs to the deployment baseline.

## Release gates

CI requires secret scanning, architecture regression checks, warnings-as-errors Release builds, security/unit tests and NuGet vulnerability reporting. **CI success does not equal production approval.** Final release still requires an isolated real AD/HR/mTLS test deployment, firewall verification and authenticated/unauthenticated DAST/penetration testing.

See `docs/ADMIN-RBAC.md`, `docs/BREAK-GLASS.md`, `docs/KIOSK-HARDENING.md`, `docs/OPERATIONS.md`, `docs/DEPLOYMENT.md`, `docs/HR-INTEGRATION.md`, and `docs/SECURITY-TEST-PLAN.md`.
