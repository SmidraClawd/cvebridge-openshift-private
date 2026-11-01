# Offer ACS when a development team requests a channel

ACS is one shared bot service. Each participating team gets its own approved
channel-to-namespace configuration. Alice and Bob are demo developers, not bot
accounts. The actual Mattermost bot is `acs`, displayed as **ACS**.

## Intended service workflow

1. A development team requests a private Mattermost channel. Offer ACS as an
   optional integration on that request; record which cluster and namespaces
   belong to the team and who owns the membership policy.
2. The platform/security owner approves the namespace scope. Connect StackRox
   Sensor to the cluster using the organization's normal deployment process.
   Choose `common` (every recipient has Kubernetes access) or explicitly approve
   `requester` (channel membership permits reading the caller's findings).
3. Add the existing ACS bot to the private channel, configure its literal
   namespace allowlist and approved identity mappings, and verify access.
4. Developers run `/cve status`, `/cve scan [namespace]`, or
   `/cve CVE-2022-40897 [namespace]`. `/acs` supports the same commands.
   Authentication links remain private. The checked group result is posted by
   the ACS bot with a risk summary, scan coverage, and package fix information.
5. Review channel membership when people join, leave, or lose cluster access.
   Shared posts remain in channel history; Kubernetes revocation cannot erase
   information already published to Mattermost.

StackRox performs workload inventory and image vulnerability scanning. ACS
requests new digest-pinned image scans with `scan`, and retrieves existing
results for a CVE lookup. The scan covers Sensor's active-pod inventory at start;
it does not execute commands inside workloads or scan arbitrary source code. No separate ACS deployment
or Mattermost administrator role is required for each developer.

## Exercise onboarding in this local lab

Create the development team's **private** channel in Mattermost and add its
developers first. Copy `config/team.example.json` into a private location and
replace the channel ID, namespaces, and any new approved identity mappings.
Use stable Mattermost user IDs, not editable usernames or profile emails.

```bash
python3 scripts/onboard.py --config /secure/path/team.json
python3 scripts/onboard.py --config /secure/path/team.json --apply
```

The first command validates without changing channel membership, app settings,
or Kubernetes grants. It checks the exact private channel, every current human
member's identity and existing namespaces. With the default `common` policy it
also verifies each member's live Kubernetes SubjectAccessReviews. Setting
`sharing_policy` to `requester` explicitly authorizes channel-wide disclosure of
the caller's findings inside the approved namespace allowlist. The application
still checks the caller's live permissions before scanning and before posting.
The second command adds the non-admin ACS bot and deploys the approved scope
only after those checks pass. It never grants namespace permissions. A private
onboarding record is saved under `.local/onboarding/`.

This administrative helper targets this installation's localhost Mattermost,
generated `labadmin` credential, private kubeconfig, and email-based user grants.
It does not create an enterprise service-catalog form or automate a ticketing
system. This guide documents onboarding in the local lab.

The lab's **Team Security** uses `requester` with `demo-team-a`, `demo-team-b`
and `demo-shared` approved. Alice scans A/shared and Bob scans B/shared. Both
read the shared cards and attached scan reports. Neither caller can initiate
a scan of the other caller's namespace. A new channel defaults to `common`.

## Operate the bot

ACS uses its own bot access token. It has ordinary Mattermost membership and can
post only where it has been added. Shared messages are created through the REST
API using that token; the stored post author is ACS's bot user ID, not Alice's.
The app rejects administrator tokens and human accounts as the configured bot.

The short private slash-command responses use the ACS display name and bot icon.
The local installer enables Mattermost's integration username/icon overrides for
those responses. On a company server, apply the organization's integration
branding policy; a disabled override affects slash-response appearance, not the
actual identity of shared posts. Do not promote the bot to administrator to
change its appearance or bypass channel permissions.

## Offer automatic scans

To approve self-service scheduling for this channel, set `enable_schedule: true`
in its operator-reviewed team JSON. Optional `schedule_managers` restricts editing
to named stable user IDs; otherwise verified team members can configure it.
Developers use `/cve schedule` to choose days, times, timezone and approved scope,
then save to activate. The same command edits or pauses it later. See
[SCHEDULING.md](SCHEDULING.md) for permissions and operational behavior.
