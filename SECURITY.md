# Security policy

Do not commit production passwords, connection strings containing SQL passwords, private keys, PFX/P12 files, TOTP secrets, recovery codes, or filled `appsettings.Production.json` files.

Production secrets should be avoided rather than hidden: run the internal broker under a gMSA and use Windows integrated authentication to SQL and AD. Portal-to-broker authentication uses a client certificate whose private key remains in the Windows certificate store on the portal host.

If a secret is committed, removal from the current file is not sufficient. Rotate it and review repository history.

Security defects that could expose credentials, bypass identity proofing, change the reset target, bypass certificate validation, or permit privileged-account reset are release blockers.
