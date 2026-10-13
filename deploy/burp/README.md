# Dedicated BugHunter Burp Deployment

The project-owned templates here install Burp Suite Community Edition as a
separate loopback-only capture service. The installed service uses a temporary
in-memory Burp project; BugHunter TrafficStore and protected Evidence persist
the observations. Do not attach Burp to production recon workers, their
browser broker, or PostgreSQL.

`bughunter-burp.service` starts the Xvfb-backed Community runtime through
`with-bridge-secret.sh` and `run_community.py`. `project-config.json` defines
four loopback proxy listeners and `user-config.json` loads the existing
capture-only Montoya extension. The bridge is target-scoped and private to
BugHunter. `local_fixture.py` and `fixtures/` support loopback-only smoke
tests; they are not live target test instructions.

`config.example.toml` is a non-secret BugHunter configuration template.
Replace its absolute paths, provision the bridge capability outside Git, and
enable Burp only after the installed service, extension, CA trust, and listener
bindings have been verified. `project_root` is BugHunter's target metadata
directory, not a persistent Community project file.

For the current installed version, service operations, startup order,
limitations, and checks, see
[`OPERATOR_BURP_COMMUNITY.md`](../../docs/OPERATOR_BURP_COMMUNITY.md).
