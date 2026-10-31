# Team-controlled automatic scans and reports

Run `/cve schedule` (or `/acs schedule`) in an approved private team channel.
Mattermost returns a private, ten-minute login link bound to the caller. The
same command opens first-time setup or the existing team configuration.

The form lets the team choose:

- Weekdays, one to four local times per day, and an IANA timezone such as
  `Europe/Stockholm`. Times must be at least one hour apart.
- Namespaces inside the administrator-approved channel and automatic-run scope.
  Adding a namespace also requires the configuring person's live Kubernetes
  permission. Another verified team member can preserve previously approved
  team scope while changing frequency.
- A fresh forced image scan followed by a report, or a report using existing
  scans. A report alone does not claim that images were freshly rescanned.
- Enabled or paused state. Nothing is enabled on the first form until Save.

At first setup, all eligible namespace checkboxes are selected. Uncheck any
namespaces the team does not want in the schedule; at least one must remain.
Selection is currently by namespace, without individual application or image
checkboxes. A scan includes images used by active pods in the selected
namespaces in Sensor's inventory at scan start, including known init-container
images. It does not scan the entire registry or unused images.

The active configuration is owned by the channel. Developers do not leave their
SSO session or a personal API token running in the background. Run `/cve
schedule` again to edit or pause, or select **Provkör senast sparade schema**
to test the saved settings. Test runs are limited to one per minute and one
queued/running test per channel; unsaved form edits are not applied by Test.

## Delivery and execution

ACS posts a configuration card containing days, times, scope and next execution.
Timed runs use the same scan summary cards and complete JSON attachment as
manual scans. Compact Swedish cards show at most three prioritized CVEs,
an action line, scanner-reported fix versions, coverage and risk counts. Fix
versions are source data, not a claim that the version remains safe today.
The full JSON report
retains Java/JAR and other package source types. The source type is not an ownership classification:
Java can also be installed by the base-image maintainer. Base-image versus
application-layer responsibility is not inferred by this integration.

The scan uses StackRox Sensor's active-pod inventory and immutable runtime image
digests, including known init-container images. Coverage warnings, failed images,
database age and per-image scan times remain visible in the report. The scanner
can identify supported packaged Java dependencies; it does not analyze arbitrary
Java source code or prove exploitability.

One worker handles manual and scheduled scans; the durable queue waits up to
five minutes for a due run. The application checks live service permissions,
channel policy and audience before scanning and before uploading/posting. A
changed revision, pause, revoked scope or changed audience prevents publishing
new findings from the old job. Failed runs are shown in history. A service
failure sends a generic failure card only if the audience remains approved.

The scheduler polls every 15 seconds and uses UTC internally. At spring DST,
a nonexistent local time is skipped. At autumn DST, a repeated local time is
executed once at its first occurrence. A computer/service outage longer than
five minutes records the old due slot as missed and advances to the next future
slot. It does not replay a backlog when the laptop wakes. The computer and
cluster must be running at the selected time.

Configuration, revision history, due-slot claims and run outcomes persist on
the existing SQLite PVC. Concurrent form edits use revision checks. State-changing
browser forms require the authenticated command owner, the expected Origin and
a secret-bound CSRF value. Requests are consumed after success. A restarted
worker marks in-flight work interrupted, without automatically posting it again.
Delivery and database commits cannot be one transaction: an interrupted network
response may leave delivery uncertain. Check the channel before retrying.

This deployment is a single application replica. Due-slot claims are durable;
it is not a multi-replica leader-election or highly available queue design.

## New-CVE mentions

Confirmed shared scan/report posts establish a per-channel, per-cluster CVE
history on the SQLite PVC. By default, the first complete report for a namespace
establishes its baseline without a mass mention. A later report containing a
previously unreported CVE with CVSS at least 9 includes one `@channel` mention.
The same CVE does not notify again after restart or disappearance/reappearance.
Ordinary reports still include unresolved findings.

This check happens when a manual or scheduled report runs. It is not a live CVE
feed. Configure `cve_alerts_enabled`, `cve_alert_min_cvss` and
`cve_alert_first_report` in deployment settings to change the defaults. Private
callbacks never mention the channel. Failed or uncertain delivery does not
deliberately advance notification history; check channel history before retrying.

| Deployment setting | Default | Meaning |
| --- | --- | --- |
| `cve_alerts_enabled` | `true` | Allow mentions in shared scan/report posts. |
| `cve_alert_min_cvss` | `9` | Minimum CVSS, from 0 to 10; use 0 for all CVEs. |
| `cve_alert_first_report` | `false` | Start without mentions; true includes initial findings. |

New means previously unreported in this channel and cluster, not newly published
globally or statistically rare. Each newly added namespace establishes its own
baseline. CVE lookups, help, database status and schedule confirmations do not
trigger this alert. A single post groups new qualifying CVEs into one mention.
Keep the SQLite volume to preserve the history; replacing it resets this state.

Mattermost must allow channel mentions, and members may configure their
[channel notifications](https://docs.mattermost.com/end-user-guide/preferences/manage-your-channel-specific-notifications)
to ignore them. The local check verifies the server's mention counter; email and
mobile push delivery are not configured in this lab. A timeout after Mattermost
accepts a post but before acknowledgment can still leave delivery uncertain;
this is not an atomic exactly-once guarantee across the two services.

## Operator approval and credentials

Automatic execution is disabled for a channel until the operator sets
`mattermost_schedule_scopes`, a subset of `mattermost_channel_scopes`:

```json
{
  "mattermost_schedule_scopes": {"ACTUAL-CHANNEL-ID": ["team-a"]},
  "mattermost_schedule_managers": {},
  "schedule_default_timezone": "Europe/Stockholm"
}
```

An empty manager map allows verified human members of an approved channel to
configure its schedule within existing access. To restrict editing, map the
channel ID to an explicit nonempty list of approved Mattermost user IDs.

The manifest creates an `acs-reporter` ServiceAccount with token automount
disabled and namespaced roles permitting only `list` on `apps/deployments` in
the approved scheduling namespaces. The integration checks that actual service
identity using SubjectAccessReview. Its own API ServiceAccount still has only
namespace-list and SAR-create privileges; neither account can impersonate users.
Remove obsolete namespace bindings through the operator's normal RBAC process
when changing scope. Configuration alone never permits an unlisted namespace.

Provide `STACKROX_SCHEDULE_TOKEN` separately from manual command credentials.
The local installer provisions the **ACS Scheduled Reporter** role and access
scope restricted to the configured cluster's approved scheduling namespaces.
Its permission set has Deployment, Cluster and Namespace read access, plus Image
read/write because StackRox requires Image write access for forced scans. The
application never exports that token to the browser or report. Definitions
freshness uses the separate existing Administration-read status token.
Use the organization's secret manager and rotation process for enterprise tokens.

The existing non-admin ACS bot posts in channels it has joined. Schedule
configuration cannot add bot membership, grant Kubernetes access, change
StackRox scope or turn a public channel into an approved destination.

The local onboarding helper accepts `enable_schedule: true` and optional
`schedule_managers` in its approved team configuration. Its `--apply` flow adds
the service's namespaced bindings and updates the local reporter access scope.
Company deployments should apply these inputs through their reviewed deployment
and identity processes. The `/cve` slash command is registered once per team;
`schedule` is another backend subcommand, not a separate incoming webhook.

## Real Java example and verification

The lab runs a pinned [Spring Boot demonstration image](https://github.com/christophetd/log4shell-vulnerable-app)
in `demo-team-a/java-sample`. It contains Log4j 2.14.1 inside the application
JAR. The image retains its upstream Apache-2.0 license. This is a deliberately
old test target, never a recommended application/base image.

The sample runs non-root, without service-account credentials, capabilities or
a writable root filesystem. HTTP binds only to pod loopback; there is no
Service or port forwarding, and namespace NetworkPolicy denies ingress/egress.
Lookup expansion is disabled as an additional lab setting. Tests inspect package
metadata and CVE findings; they do not send exploit payloads to the application.

```bash
python3 -m unittest discover -s tests -v
python3 scripts/verify.py
python3 scripts/verify_scheduling.py
```

The final script exercises a real upcoming clock time and may take a few minutes.
It checks owner/CSRF/scope controls, configuration changes by another team member,
Java findings, actual forced scan timestamps, shared report download and pause.
It leaves the demonstration channel enabled for daily 08:00 Europe/Stockholm
scans of `demo-team-a` and `demo-shared`. The result is saved in
`.local/scheduling-verification.json`. Change the demonstration schedule with
`/cve schedule` after testing. Nothing is scheduled on an untouched installation
until a team saves its first configuration.
