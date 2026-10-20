# Operator cleanup in HackBot

The authenticated dashboard gateway requires CSRF for every cleanup mutation.
These actions operate on BugHunter-owned state only; none writes to recon or
sends target traffic. ObjectFactory's existing **Cleanup object** is different:
it may contact the authorized target and still requires its normal scope,
permit, rate, budget, and cleanup policy checks.

| Control | Effect | Preserved |
| --- | --- | --- |
| Delete browser session | Stop its managed Chromium context, release its Burp binding and admission slot, and hide the session from active lists | Session tombstone/events, TrafficStore, Evidence, identity attribution; profile bytes remain until reviewed retention cleanup |
| Remove account | Refuse while any undeleted session remains; disable the registry identity and remove non-secret `accounts.yaml` metadata | Identity ID and historical attribution, traffic, findings, secret-provider references |
| Clean Target Runtime | Stop and retire up to 20 target sessions and release up to 20 orphaned target Burp bindings after active-work checks | TargetPackage, accounts, evidence, history, recon |
| Delete Target | Require an exact package-ID confirmation and zero dependencies; disable registered identities and remove the validated file-backed package | Registry target ID, service tombstone, evidence, traffic, validations, findings, reports, audit history, recon |
| Archive campaign, run, or hypothesis | Append an operator archive event and hide from the default list; **Show archived** includes it again | Complete audit/evidence history and direct detail access |

For a stale anonymous session: open **Sessions**, select the target, find the
`STOPPED` or `REAUTH_REQUIRED` row, click **Delete**, and confirm. The row
disappears immediately. The browser admission count and Burp listener allocation
are available for reuse without restarting HackBot. A `RUNNING` row is stopped
through the normal manager before retirement. Deletion fails closed while active
target work could be using the session. The VNC/Xvfb services are shared
installation services, not per-session processes, so they remain running.
Profile bytes are not purged by Delete: the existing anonymous/disabled/named
profile-retention review and grace-period rules still apply to retired sessions.

For account removal: open **Targets**, select the target, open **Accounts**, and
click the account's Remove control. If sessions exist, delete them from
**Sessions** first. Removing the account does not erase or revoke external
secret-provider material; manage those separately.

For target deletion: open **Targets**, select the target, use **Clean Target
Runtime** if only sessions remain, then click **Delete Target**. The dialog
shows exact dependency counts. Finish or cancel active campaigns/planners,
bootstrap/behaviour runs, approvals, pending object cleanup, and continuous
watch before deletion. Type the exact package ID and confirm. The target then
appears under **Deleted target history** as `<package-id> (deleted)`. A deleted
package ID cannot be silently reused because historical registration remains.

No unrestricted deletion is exposed for Evidence, TrafficStore, validation
records, confirmed findings, submitted report history, or executed plans.
Draft plans also remain visible because the current plan store has no safe
archive event contract; a future reviewed schema change is needed before that
control can be offered. Research briefs, learned behaviour, and API registry
records have no operator reset here because the existing rebuild contracts do
not yet prove complete reference-safe regeneration. Existing retention/GC
actions remain separate, reviewed workflows.

Deletion can fail after stopping a browser or disabling an identity; that is a
fail-closed partial cleanup. Refresh the preview and complete the remaining
step. The target package removal is an atomic rename out of the active root
followed by bounded local file cleanup. An interrupted file cleanup can leave a
hidden `.deleted-target-*` quarantine directory for manual inspection; it is
never loaded as an active TargetPackage.
