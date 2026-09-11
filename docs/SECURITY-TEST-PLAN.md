# Security and end-to-end acceptance plan

The platform is not production-ready merely because it compiles. Release requires all automated gates plus an isolated AD/HR integration test and attack testing.

## Automated CI gates

1. Plaintext-secret scan.
2. Architecture regression scan: no DMZ SQL/LDAP references; no certificate-validation bypass; no legacy unsafe API routes; nested provisioning-group validation must remain enabled; user-selectable profiles/groups must also be on positive allow-lists; append-only SQL audit trigger must exist; assisted PIN entry must remain masked.
3. Release build with warnings treated as errors and current analyzers.
4. Unit/security tests for PIN verification/lockout, HR corroboration, positive provisioning allow-lists, TOTP/API replay, reset-transaction binding, password policy/blocklist, local break-glass controls and append-only audit behavior.
5. NuGet vulnerable dependency report.

## Isolated integration / E2E environment

Use dedicated test HR records, a dedicated AD test OU/domain scope, real gMSA delegation, real LDAPS certificates, actual SQL TLS and the real portal-to-broker mTLS pattern. Do not grant the service identity rights over production user OUs during acceptance.

Exercise at least:

- existing user + enrolled TOTP -> authenticated profile/photo -> confirmation -> password reset;
- existing user + secure PIN -> profile/photo -> reset;
- admin-assisted registration: AD helpdesk login -> HR photo verification -> member privately chooses PIN -> verifier stored -> member uses PIN -> TOTP enrollment -> reset;
- first-time user -> AD account absent -> create disabled account in `Newly Created User` -> TOTP -> set password -> account enabled;
- existing employeeID -> link existing AD object, never duplicate;
- email/account/employeeID collision -> fail closed into review queue; correct condition then safe admin retry;
- review manual close requires resolution note and audit;
- three wrong PINs -> PIN method locked while already-enrolled TOTP remains usable;
- TOTP replay and API request-ID replay rejected;
- reset transaction rejected from changed source IP/mTLS client and after expiry/use;
- AD RBAC: helpdesk cannot provision; provisioning admin cannot manage break-glass; auditor cannot mutate; non-admin denied;
- nested configured group whose ancestor is privileged -> profile application rejected;
- AD unavailable during group-safety validation -> provisioning fails closed;
- HR inactive/ambiguous employee -> generic denial and no profile disclosure;
- invalid/expired client certificate -> sensitive internal API unavailable;
- kiosk idle timeout/session wipe/back-button behavior;
- Internal `/health/ready` fails when HR, security DB, LDAPS or DP key path is intentionally unavailable.

## DAST / penetration testing

Run authenticated and unauthenticated DAST against the deployed test DMZ site and internal admin application. Target account enumeration, CSRF, XSS, injection, host-header abuse, forwarded-header spoofing, rate-limit bypass, IDOR, replay, session fixation, cache/profile-photo leakage, error-detail disclosure, administrative authorization bypass, mTLS bypass, provisioning-code manipulation and duplicate-account creation.

Verify network policy independently: DMZ -> internal identity service TCP/443 only; DMZ -> AD/LDAP, HR/SQL, SMB, RDP, WinRM and general internal networks denied/logged.

## Production sign-off evidence

Record build SHA, date, tester, HR records/domain/OU used, actual vs expected result, correlation IDs/log evidence, dependency/DAST results, firewall evidence and approvals. Any failed security test blocks production release.
