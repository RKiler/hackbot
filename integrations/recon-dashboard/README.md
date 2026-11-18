# Recon Dashboard Integration

This directory contains the same-origin Flask gateway and browser assets used by
the deployed `/hackbot` interface on `recon.base64.live`.

The BugHunter control plane remains a separate service. The dashboard connects
to it through the Unix socket at `/run/bughunter-agent/control.sock`; the
gateway never forwards browser credentials to BugHunter.

## Files

- `hackbot_gateway.py`: authenticated, CSRF-protected route facade.
- `templates/hackbot_panel.html`: operator interface shell.
- `static/hackbot_panel.css`: dashboard styling.
- `static/hackbot_panel.js`: operator-side UI behavior.
- `tests/`: gateway, UI, and operator-workflow coverage.

## Flask installation

Copy or mount the gateway, template, and static assets into the recon dashboard,
then register the routes after the dashboard authentication helpers exist:

```python
from hackbot_gateway import install_hackbot_routes

install_hackbot_routes(
    app,
    authorized=dashboard_authorized,
    csrf_token=dashboard_csrf_token,
    require_csrf=require_dashboard_csrf,
    auth_enabled=lambda: bool(config.get("dashboard", {}).get("auth", {}).get("enabled", False)),
    hunt_ui_enabled=os.environ.get("HACKBOT_HUNT_UI_ENABLED") == "1",
)
```

The exact helper names are dashboard-specific. Authentication and CSRF checks
must remain server-side. Mount `/run/bughunter-agent` read-only into the
dashboard container so it can access the control socket.

## Excluded runtime state

Production configuration, operator credentials, target packages, cookies,
tokens, browser profiles, traffic, evidence, databases, and vault files are not
part of this source integration and must not be committed.
