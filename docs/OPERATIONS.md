# Operations, HA/DR, monitoring and retention

## Health endpoints

- DMZ Portal `/health/live`: process liveness.
- DMZ Portal `/health/ready`: verifies the Internal Identity Service readiness endpoint using the configured mTLS HTTP client.
- Internal Service `/health/live`: process liveness.
- Internal Service `/health/ready`: verifies security SQL, HR SQL/view, validated LDAPS and Data Protection key-path availability.

Load balancers should remove a node from service when readiness fails but should use liveness independently for restart decisions.

## Data Protection and HA/DR

TOTP secrets and other protected internal state depend on ASP.NET Core Data Protection keys. A single-server deployment may use an ACL-protected local key directory. For redundant/DR nodes, use a protected shared/recoverable key location and configure `DataProtection:KeyEncryptionCertificateThumbprint`; set `RequireCertificateProtection=true` in production once the certificate is deployed. Grant key-path access only to the service identity and backup/recovery operators.

The DMZ portal can likewise use a shared protected key ring (`Portal:DataProtectionKeyPath`) and certificate for TempData continuity across redundant nodes. Losing the portal key ring invalidates in-progress recovery sessions; losing the Internal Service key ring can make stored TOTP material undecryptable, so internal key recovery must be tested.

## Security events and SIEM

Critical audit events are emitted through structured `ILogger` records for collection by the organization's Windows/IIS/logging/SIEM pipeline. Optional security-alert email delivery can additionally notify designated recipients. Alert delivery has retry tracking in the security database.

Recommended SOC alerts include break-glass login/rotation, repeated authentication failures, PIN issue/assisted registration, authenticator revocation, account auto-provisioning, provisioning conflicts, self-service disablement, protected-account attempts and provisioning changes.

## Retention

The built-in retention worker removes only transient operational data after configurable periods: expired API replay markers/reset transactions, used recovery codes, old throttle entries, old closed review records and alert-delivery state. `IdentityAudit` is not automatically purged by the application and is append-only at both EF/application and SQL trigger levels. Establish an organizational audit retention/archive policy and forward long-term evidence to protected SIEM/archive storage.
