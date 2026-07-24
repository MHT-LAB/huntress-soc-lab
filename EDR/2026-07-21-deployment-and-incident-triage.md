# 2026-07-21 — EDR Deployment + Full Incident Triage

## Exercise 1 — Deploy EDR, read the dashboard like an analyst
2 of 3 trial EDR endpoints deployed. Second agent pushed via RMM automation
(fleet deployment, not a manual installer) — an MSP/SOC operational skill on
its own. Third agent deployed to a disposable VM for controlled testing.
Walked the console end to end: agent overview → events feed → per-detection
"View Investigation" pane. Confirmed the analyst-note field is empty on
auto-resolved detections (`Reason Closed: N/A`) vs. a deeper investigated one.

## Exercise 2 — Trigger and triage a detection end to end
No official Huntress test-alert tool exists, so I ran Atomic Red Team
(`Install-AtomicRedTeam -getAtomics -Force`) on a disposable VM to generate
legitimate detection traffic — this pulled the full public atomics library,
not just the two techniques intended (T1547.001 Registry Run Key, T1053.005
Scheduled Task).

Microsoft Defender (managed by Huntress at no extra cost, surfaced as "MAV
Threat") blocked a wave of the resulting payloads between 21:13:13–21:14:10
UTC:
- `HackTool:PowerShell/PowerSploit.F` — credential dumping (T1003.001)
- `Trojan:Win32/PShellBr.YA!MTB`
- `VirTool:Win32/Meterpreter` — process injection (T1055.003/T1055.012)
- `Trojan:PowerShell/Powersploit.M` — keylogger (T1056.001)
- `Backdoor:JS/Relvelshe.A` — regsvr32 proxy execution (T1218.010)
- `Ransom:Win32/CVE` — bundled ransomware test file

**Escalation:** 29 accumulated remediation actions triggered Huntress's
automated containment — the host was network-isolated and a formal
High-severity Incident (#2308927) opened with a full SOC report. The report
correctly identified Atomic Red Team adversary emulation, flagged every
blocked file with timestamps, and surfaced a secondary finding (a
`defaultuser0` local admin account) that I recognized as a benign Windows
OOBE placeholder, not an attacker artifact — and did not escalate it.

**My verdict, sent to the vendor:** confirmed this was sanctioned internal
testing on an isolated trial VM, not a real compromise, and that the flagged
account was benign. No further remediation beyond the automatic quarantine.

**Why it matters:** demonstrates the full loop — detection → automated
containment → human-quality incident report → correct triage → vendor
communication — not just "an alert fired."

**Lesson for next time:** scope `Install-AtomicRedTeam` to specific
techniques instead of the full library, or only run it on hosts you're
prepared to see isolated.
