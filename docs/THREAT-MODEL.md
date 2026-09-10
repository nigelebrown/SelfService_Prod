# Threat model summary

| Threat | Control |
|---|---|
| Personnel-data disclosure gives attacker DOB/TRN/name | Static fields only locate a record; TOTP/recovery possession factor is mandatory |
| User supplies another officer's email/account | Reset target is never accepted from the browser; AD GUID/account come from authoritative data |
| DMZ web server compromised | No AD/SQL password or route; client certificate only authorizes the narrow broker endpoint |
| Stolen/guessed TOTP | 30-second TOTP, small clock window, replay step stored and rejected, throttling |
| Recovery code database stolen | Only SHA-256 hashes of high-entropy one-time codes are stored |
| Service credential leaked from config | Broker uses gMSA/integrated authentication; no reusable AD/SQL password in config |
| Rogue LDAPS endpoint / MITM | Standard OS certificate validation; no TrustAnyCertificate callback |
| Privileged account targeted | Member-OU search base, explicit deny list, `adminCount=1` rejection, denied protected groups, AD ACL backstop |
| Bot/brute-force attempts | Portal IP limiter plus broker durable source/account throttling and increasing delay |
| NAT causes mass account lockout | Account throttling uses delay rather than hard account lock; source block threshold is configurable/high |
| TOTP/recovery secret logged | Secret/password-bearing models redact `ToString`; raw passwords/TOTP/recovery codes are not audit fields |
| App restart clears security state | Enrollment, replay step, recovery use, audit and throttling are stored in SQL |
| Invalid production settings | Startup validation fails closed |
