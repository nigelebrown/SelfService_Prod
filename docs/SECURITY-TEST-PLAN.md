# Security and end-to-end acceptance plan

The platform is not production-ready merely because it compiles. Release requires all automated gates plus an isolated AD/HR integration test.

## Automated gates

1. Plaintext secret scan.
2. Architecture regression scan: no DMZ SQL/LDAP references, no certificate-validation bypass, no legacy reset endpoints, no privileged group in a default provisioning profile.
3. Release build with warnings treated as errors and latest recommended analyzers.
4. Unit/security tests for PIN hashing, HR corroboration, provisioning-policy authorization, API replay prevention, TOTP replay behavior, recovery codes, and password policy.
5. NuGet vulnerable dependency report.

## Integration / E2E test environment

Use a dedicated test domain/OU and test HR view. Do not grant the service account rights over production users during acceptance.

Exercise at least these paths:

- Existing user + enrolled TOTP -> profile/photo -> password reset.
- Existing user + secure PIN -> profile/photo -> reset.
- First-time user + PIN + HR corroboration -> AD account absent -> create disabled account in `Newly Created User` -> enroll TOTP -> set password -> account enabled.
- Existing HR employee with existing AD employeeID -> link existing object, never duplicate.
- Email/account collision with a different employeeID -> no creation; admin review generated.
- Wrong PIN three times -> PIN method locked; TOTP remains available if enrolled.
- TOTP replay -> second use of same timestep rejected.
- Reset transaction from different source IP or client certificate -> rejected.
- Expired/reused reset token -> rejected.
- Duplicate API request ID -> rejected.
- Non-admin Windows identity -> admin console denied.
- Blocked privileged group in a provisioning profile -> startup/policy rejection.
- HR inactive employee -> no recovery/provisioning.
- Ambiguous HR lookup -> generic denial and no profile disclosure.
- Invalid/expired client certificate -> internal API unavailable to caller.

## Security attack tests

Run authenticated and unauthenticated DAST against the DMZ site, plus targeted tests for account enumeration, CSRF, XSS, injection, host-header abuse, forwarded-header spoofing, rate-limit bypass, IDOR, replay, session fixation, caching of HR photographs, and error-detail disclosure. Verify firewall policy blocks DMZ -> AD/LDAP, SQL, SMB, RDP, WinRM and permits only DMZ portal -> internal broker TCP/443.

## Production sign-off evidence

Record test date, build SHA, tester, domain/OU used, expected/actual result, screenshots/log correlation IDs, vulnerability-scan result, and approval. Failed security tests block deployment.
