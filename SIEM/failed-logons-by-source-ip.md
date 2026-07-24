# SIEM — Failed Logons by Source IP

**Goal:** build a saved search/alert surfacing a source-IP pattern —
specifically repeat failed-logon activity, the classic brute-force /
credential-stuffing signal — rather than just a single event.

## Query (ES|QL)

First attempt failed to save:
```
from logs
| where event.code == 4625
| where winlog.event_data.IpAddress != "-"
| where winlog.event_data.IpAddress != "127.0.0.1"
| STATS count(*) BY winlog.event_data.IpAddress, winlog.event_data.TargetUserName
| keep winlog.event_data.IpAddress, winlog.event_data.TargetUserName, `count(*)`
```

Error: `Failed to parse query: Invalid field list: \`count(*)\``. The
trailing `keep` referenced the auto-named aggregation column
(backtick-quoted `count(*)`), which didn't parse in this environment.

Fixed version — alias the aggregation instead of relying on the special-
character default name, and drop the now-redundant `keep` (`STATS ... BY`
already limits output to the aggregation + grouping columns):
```
from logs
| where event.code == 4625
| where winlog.event_data.IpAddress != "-"
| where winlog.event_data.IpAddress != "127.0.0.1"
| STATS failed_attempts = count(*) BY winlog.event_data.IpAddress, winlog.event_data.TargetUserName
```

This saved successfully.

## Generating real test traffic

Event 4625 = failed logon. A local console failure won't populate
`IpAddress` (it logs as `-`), so the test needed a genuine remote auth
attempt. RDP over a Tailscale connection turned out to be the cleanest
path — it avoided both a NAT'd VM (unreachable from outside the host
without a port-forward rule) and an SSH setup where key-based auth would
have auto-succeeded before ever prompting for a password.

Deliberately failed an RDP login twice against a Windows endpoint.

## Verifying locally before trusting the SIEM

Checked the Windows Security log directly first:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=(Get-Date).AddMinutes(-30)}
```

Confirmed 2 real events, both with a populated source IP. Notably,
`LogonType` was `3` (Network), not `10` (RemoteInteractive) — because NLA
(Network Level Authentication, the Windows default) validates credentials
over CredSSP *before* an RDP session is ever created. A failed attempt
under NLA never reaches the "session" stage, so it logs under the network
auth type instead. A query that only filters `LogonType == 10` would
silently miss RDP brute-force failures entirely — it would only ever catch
a successful session, or a failure with NLA turned off.

## Results

| failed_attempts | IpAddress | TargetUserName |
|---|---|---|
| 2 | 100.x.x.x *(redacted — personal Tailscale IP)* | *(redacted — personal account)* |

Matched exactly against the local Windows Event Log — same timestamps,
same IP, same LogonType (specific IP/username redacted above; the match
itself is what confirms the pipeline). Confirms the full pipeline end to end: RDP
failure → Windows Security log → Huntress SIEM ingestion → saved search.

## Why source IP, not just event ID

A single 4625 is noise; a source IP with a repeated count is the actual
detection story. This is the same pattern Huntress's own SOC uses to catch
real RDP/SMB brute-force campaigns from internet-facing exposure — the
difference here is scale (2 deliberate attempts vs. a real campaign's
hundreds), not the underlying logic.
