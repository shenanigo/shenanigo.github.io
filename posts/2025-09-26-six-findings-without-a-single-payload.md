---
title: "Six Findings Without a Single Payload"
date: 2025-09-26
type: research
tags: [Web, Recon, CVE-Triage, Disclosure]
---
A passive technology fingerprint of a file-sharing web application surfaced an entire stack of outdated front-end libraries sitting on top of an end-of-life server platform. Six coordinated disclosures came out of it — and not one required sending a malicious request. This is the long version: every finding, why it mattered, and how each was classified without overstating it.

## Passive recon: reading the stack

Wappalyzer/BuiltWith-style fingerprinting infers an app's technology from what it already serves everyone: response headers, asset filenames, version banners embedded in library files, and global objects exposed on the page. It's completely passive — no fuzzing, no payloads, nothing that could be mistaken for an attack. For an outsider doing a first pass, it's the cheapest possible map of where the known-CVE surface probably lives.

The fingerprint flagged more components than ended up as findings. Only the ones whose *confirmed* version carried a genuinely applicable CVE made the cut — dropping the version-range false positives instead of reporting everything the tool screamed about is half the work, and the half that earns a triager's trust.

## Finding 1 — End-of-life server platform

Response headers placed the application on IIS 8.5, which ships with Windows Server 2012 R2. Extended support for that platform ended on 10 October 2023. After an end-of-life date the vendor stops shipping security patches entirely, so every vulnerability discovered from that point on simply accumulates on the box, unpatched, with no fix ever coming.

A single outdated library is a known-vulnerable component you can swap out; an end-of-life operating system is a known-vulnerable *foundation* under everything else, and the risk only compounds with time. This was filed first and on its own — both because it's the highest-impact item and because the program rejected aggregated findings. Remediation is a platform migration to a supported Windows Server release, not a patch.

## Finding 2 — Handlebars (prototype pollution)

The Handlebars templating library was several versions behind. Older Handlebars releases carry prototype-pollution vulnerabilities, and in server-side template-compilation contexts some of those pollution paths have been chained to code execution.

The honest classification took restraint. Client-side, this is prototype pollution, and that's how it was filed — not as remote code execution, which only applies under specific server-side conditions I had no evidence were present. Claiming RCE on a version-identified finding with no demonstrated server-side compile path is exactly the kind of overreach that gets a whole report binned. Remediation: upgrade to a current Handlebars release.

## Finding 3 — jQuery UI 1.13.x (XSS + dialog DoS)

jQuery UI — a separate library from jQuery core — sat on a 1.13.x release before 1.13.2. That range includes an XSS in the checkboxradio widget (CVE-2022-31160), XSS exposure in the datepicker where untrusted input is bound to options like `altField` or the `*Text` settings, and a denial-of-service in the dialog widget where attacker-controlled titles get rendered. All fixed in 1.13.2.

Beyond the version bump, the practical hardening note is to never bind untrusted input into those datepicker options, or into `.position()`'s `of` option.

## Finding 4 — jQuery 3.1.x (prototype pollution + XSS)

This one came with a memorable detail: the scanner reported jQuery `3.1.13` — a version that was never released. The 3.1 line stops at 3.1.0 and 3.1.1, so the "13" was a parsing artefact. Confirming the real version from the file banner (or `jQuery.fn.jquery` in the console) put it in the genuine 3.1.x range — old enough to carry three well-known CVEs.

Those are prototype pollution in `jQuery.extend(true, ...)` (CVE-2019-11358, fixed in 3.4.0), and XSS through HTML-manipulation methods like `.html()` and `.append()`, including `<option>` handling (CVE-2020-11022 / CVE-2020-11023, fixed in 3.5.0). All client-side and conditional on the app feeding untrusted input into those APIs. The fix is gratifyingly boring — 3.1 to the current 3.7.1 is largely drop-in, since the painful breaking changes were back at the 2.x to 3.0 jump.

## Finding 5 — DataTables 1.10.16 (prototype pollution)

The DataTables plugin was on 1.10.16, inside the 1.10.9–1.10.21 range affected by CVE-2020-28458, a prototype-pollution issue. It was filed as prototype pollution — mapped to "Other → Prototype Pollution" in the program's taxonomy, because no honest "XSS" or "RCE" box fit the actual defect. Remediation: move past the affected range to a current DataTables build.

## Finding 6 — Moment.js (ReDoS)

Moment.js was the last finding, and a good illustration of why CVE *selection* matters as much as finding the bug. Moment carries more than one CVE, including a path-traversal issue (CVE-2022-24785) and a regular-expression denial-of-service. For the submission I led with the ReDoS CVE (CVE-2017-18214), because the impact I was claiming was denial of service — citing the path-traversal CVE under a DoS classification would have been an internal contradiction a triager catches in seconds.

Worth noting too that Moment is in maintenance mode and its own maintainers steer new projects elsewhere, so the cleanest remediation is migrating to a modern date library rather than just bumping the version.

## Triage honestly, or lose the triager

A running theme across all six: report each component as exactly what it is. The temptation with a stack this stale is to inflate — every prototype pollution becomes "RCE," every client-side XSS becomes "critical," the whole thing gets aggregated into one scary mega-finding. That's how you get rejected, and how your next report gets read with a raised eyebrow.

Each item went in as "version-identified, exploitability conditional," mapped to the most accurate vulnerability type rather than the scariest available one, with a CVE-ID that actually matches the claimed impact. Medium-severity findings only land when the triager can trust every line.

## Coordinated disclosure, one finding at a time

The program enforced two rules that shaped the whole submission: no aggregated reports, and only one open submission at a time. So the six went in sequentially, in priority order — the end-of-life platform first, then the libraries by descending impact. Annoying as a process, but honestly the right way to report this kind of work anyway: one clean, single-issue report at a time, each standing or falling on its own merits.

## Takeaway

Outdated dependencies and end-of-life infrastructure are the least glamorous findings in security, and by sheer volume among the most common real-world risk. You don't need an exploit chain to surface them — passive recon does it in minutes, with zero traffic that looks like an attack. What turns that raw list into something a defender will act on isn't the size of the list or the drama in the writeup; it's accurate classification, CVE mapping that matches the claimed impact, and the restraint to call each component exactly what it is. Six findings, no payloads, and a report a triager could trust end to end.
