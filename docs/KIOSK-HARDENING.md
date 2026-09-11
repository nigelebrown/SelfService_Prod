# Recovery kiosk hardening

The portal supports a kiosk mode, but browser code cannot replace operating-system kiosk controls.

## Application controls

Set `Portal:KioskMode=true` and `Portal:KioskIdleMinutes` to the approved short timeout (default 3 minutes). Kiosk mode:

- redirects an idle browser to `/ResetSession`;
- clears server-side TempData/session transaction state;
- requests clearing of browser cache/storage for the site;
- prevents back-forward-cache restoration from reviving a prior screen;
- sends `Cache-Control: no-store`, `Pragma: no-cache`, `X-Robots-Tag`, CSP, frame and referrer protections;
- displays an explicit warning never to disclose a PIN/authenticator code/password to staff or callers.

## Windows/browser baseline

Use Windows Assigned Access or equivalent managed kiosk mode. Use a dedicated standard kiosk OS account with no local administrator rights. Restrict navigation to the recovery portal, disable browser password saving/autofill/sync/developer tools/downloads/printing where operationally possible, clear browser profile data at sign-out/reboot, patch automatically, enforce screen lock/reboot policy, block removable storage if not required, and prevent access to internal administrative URLs through network/firewall policy.

The kiosk should reach only DNS/NTP as required and the approved HTTPS portal endpoint. It does **not** need direct HR, SQL, LDAP or AD connectivity.

Privacy screen placement and physical supervision are operational controls; no web application can reliably prevent a photograph of the screen.
