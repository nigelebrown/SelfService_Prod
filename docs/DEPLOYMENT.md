# Deployment

## Package 1 — DMZ Portal

Publish the portal project as the `IdentityRecovery.DmzPortal` assembly. Place it on a dedicated DMZ Windows/IIS host or hardened reverse-proxy application host that is **not domain joined**.

Required properties:

- public/user-facing HTTPS certificate on the reverse proxy/IIS binding;
- a separate non-exportable client-authentication certificate used only for portal -> internal-service mTLS;
- Kestrel bound to loopback behind IIS/reverse proxy;
- exact `AllowedHosts` value and exact trusted proxy IP when forwarded headers are used;
- firewall permit only DMZ portal IP -> Internal Identity Service IP TCP/443;
- firewall deny/log DMZ -> AD/LDAP, SQL, SMB, RDP, WinRM and general internal subnets;
- no SQL, LDAP, domain credentials, HR credentials, PIN store or TOTP secret store on the DMZ host.

## Package 2 — Internal Identity Service

Publish the broker project as the `IdentityRecovery.InternalService` assembly on a dedicated domain-joined Windows/IIS application server in an internal application-security zone.

Required properties:

- application pool/service runs as a least-privileged gMSA;
- server-authentication TLS certificate with a valid DNS SAN and trusted chain;
- API accepts only allow-listed portal client certificate(s);
- SQL uses `Integrated Security=True;Encrypt=True;TrustServerCertificate=False`;
- LDAPS uses the DC FQDN and validates the DC certificate;
- gMSA is delegated only the required reset/create/move/group rights on the intended user OUs/groups and is not a Domain Admin/Account Operator;
- data-protection key path is ACL-restricted;
- `IDENTITY_RECOVERY_PIN_PEPPER` is injected outside source/config as base64 for at least 32 random bytes;
- admin console uses Windows Authentication and a dedicated administrator AD group SID allow-list.

## HR/personnel source

Create a read-only identity-recovery view matching `docs/HR-INTEGRATION.md`. Only the Internal Identity Service receives database/network permission to this source. The DMZ host must not.

## Security store

Run `database/schema.sql` against the dedicated Identity Recovery security database. Grant the gMSA only the application permissions required for these tables. The store contains PIN verifiers/salts, protected TOTP secrets, recovery-code hashes, identity links, reset transactions, throttle/replay data, provisioning reviews and audit records; it must never contain plaintext PINs or passwords.

## Provisioning policy

Configure one default low-privilege staging profile, normally targeting `OU=Newly Created User,...`. Add only baseline groups. Configure all privileged groups in both the provisioning and directory deny lists. Additional profiles can map approved codes to approved OUs/groups; mark `UserSelectable=false` for profiles intended only for administrators.

## Acceptance environment

Do not first exercise provisioning against production users. Use an isolated test OU/domain and test HR records. Validate the full matrix in `docs/SECURITY-TEST-PLAN.md`, including duplicate/collision behavior, PIN lockout, TOTP replay, transaction binding, account enablement sequencing, admin authorization and firewall isolation.
