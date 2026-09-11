# Deployment

## Package 1 — DMZ Portal

Publish `IdentityRecovery.DmzPortal` to a dedicated DMZ Windows/IIS or hardened reverse-proxy application host that is **not domain joined**.

Required controls:

- public/user-facing HTTPS certificate;
- separate non-exportable client-auth certificate for portal -> Internal Service mTLS;
- Kestrel loopback-only behind IIS/reverse proxy;
- exact `AllowedHosts` and exact trusted proxy IP when forwarded headers are enabled;
- firewall permit only DMZ portal IP -> Internal Service IP TCP/443;
- deny/log DMZ -> AD/LDAP, HR/SQL, SMB, RDP, WinRM and general internal subnets;
- no SQL, LDAP, domain, HR, PIN or TOTP credential store on the DMZ host.

For redundant portal nodes configure a shared/recoverable `Portal:DataProtectionKeyPath`, a key-encryption certificate thumbprint and `RequirePersistentDataProtection=true`.

For dedicated recovery kiosks enable `Portal:KioskMode`, use a short idle timeout and apply the OS/browser controls in `KIOSK-HARDENING.md`.

## Package 2 — Internal Identity Service

Deploy to a dedicated domain-joined Windows/IIS application server in an internal application-security zone.

- Run application pool/service as a least-privileged gMSA.
- Use server TLS certificate with correct DNS SAN/trust chain.
- Allow only the configured portal client certificate(s) on sensitive API calls.
- SQL: Integrated Security + encryption + certificate validation.
- AD: DC FQDN over validated LDAPS 636.
- Delegate gMSA only reset/create/move/approved-group rights on intended scopes; never Domain Admin/Account Operator.
- Restrict Data Protection key directory ACLs. For HA/DR use shared/recoverable storage and certificate encryption; test restoration before production.
- Inject PIN and local-admin peppers outside source/config as independent >=256-bit random base64 secrets.
- Install/maintain the approved offline password blocklist.

## AD administrative groups

Create separate AD security groups and place their SIDs into `AdminAuthorization`:

- `PlatformAdminGroupSids`
- `HelpdeskGroupSids`
- `ProvisioningAdminGroupSids`
- `SecurityAdminGroupSids`
- `AuditorGroupSids`

Manage administrators in AD, never individually inside the application. Keep Platform Admin membership minimal.

## Provisioning policy

The default staging profile normally targets `OU=Newly Created User,...`. Self-service profiles must appear in `SelfServiceAllowedProfileCodes`, and every group in a self-service profile must also appear in `SelfServiceAllowedGroupDns`. The service continuously checks configured groups for nested/transitive privileged ancestry and fails closed when validation is unavailable.

## Security store and monitoring

Run `database/schema.sql`. Grant only required SQL permissions to the gMSA. Configure structured application logs into the existing SIEM/log collection pipeline and optionally enable `SecurityAlerts` recipients through the existing SMTP relay. Keep audit history under the organization's retention policy; the app only cleans transient state.

## Acceptance

Do not first exercise provisioning against production users. Use isolated AD scope and test HR records. Complete `SECURITY-TEST-PLAN.md`, including real gMSA delegation, certificates, mTLS, firewall isolation, DAST and role-separation tests. CI alone is not production sign-off.
