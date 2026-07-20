---
title: "wp2shell: An Intelligence Assessment of CVE-2026-63030 / CVE-2026-60137"
date: 2026-07-20
type: research
tags: [CTI, WordPress, RCE, Vulnerability Analysis, Detection Engineering]
---

## BLUF

wp2shell, a pre-authentication RCE chain in WordPress Core disclosed 17 July 2026, is publicly
exploitable and under confirmed in-the-wild exploitation. I assess **with high confidence** that
mass opportunistic exploitation is underway.

Severity is not the interesting part. No IOCs are public, the exploit looks like ordinary REST
traffic, and the exposed population skews toward unmanaged instances. So **exposure is bounded by
asset inventory quality, and compromise assessment cannot currently be IOC-driven**. Anyone who
patches fast and still gets hit will be compromised through a site they forgot they owned, and
will find out behaviourally or not at all.

## Key Judgments

**KJ-1 (high).** Exploitation is occurring and is within reach of low-skill actors. Hexastrike saw
attempts in honeypots the weekend after disclosure and has assisted IR in confirmed attacks;
Patchstack confirmed independently; multiple public PoCs landed on GitHub within hours. *High:
multiple independent confirmations, not inference.*

**KJ-2 (high).** AI-assisted analysis collapsed the disclosure-to-exploitation window to near
zero, and I assess this is now the default assumption for open-source targets. Rapid7 predicted
exactly this on 17 July; Kues has since said no researcher could have completed the chain in ten
hours without AI. *High: discoverer and prediction agree, outcome observed.*

**KJ-3 (moderate).** Detection is unusually hard for a bug this severe. Per Hadrian, the exploit
is a single POST to a legitimate core endpoint with well-formed JSON, no metacharacters, no
traversal, nothing long enough to trip length rules, and hard to separate from block editor batch
traffic. Sites that strip the generator version string, a routine hardening step, lose the one
passive signal flagging an affected version. *Moderate: strong claim, single source, uncorroborated.*

**KJ-4 (moderate).** Compromise will usually lead to commodity monetisation rather than lateral
movement. *Based on the mass-WordPress-compromise ecosystem generally, not wp2shell reporting.
Held loosely: execution lands on the web server with database access, and on shared hosting the
blast radius exceeds the single site.*

**KJ-5 (low).** Many organisations will patch and close the matter without compromise assessment.
*A prior from similar events. More warning than finding, and Gap 1 makes doing better harder.*

## Evidence Base

| CVE | Type | Component | CVSSv3 | Introduced |
|---|---|---|---|---|
| CVE-2026-63030 | REST batch-route confusion | `/wp-json/batch/v1` | 9.8 | 6.9 |
| CVE-2026-60137 | SQL injection | `author__not_in` in `WP_Query` | 5.9 | 6.8 |

The access-control flaw carries the severity, not the injection. CVE-2026-60137 is standalone on
6.8.x; the full chain needs CVE-2026-63030, so only 6.9.x and 7.0.x are exploitable to RCE.

**Mechanism.** Per Hadrian's reconstruction from the patch, batch dispatch keeps three parallel
lists (`$requests`, `$validation`, `$matches`) and depends on all three staying index-aligned. In
`WP_REST_Server::serve_batch_request_v1()`, a sub-request that fails to parse is appended to
`$validation` and skipped via `continue`, never reaching `$matches`. `$matches` is now one element
short, and the dispatch loop indexes straight into it. Every later sub-request is dispatched
against the route, handler, and permission callback of the *next* one in the batch, so controlling
sub-request order means controlling which request is evaluated against which permission check.

The interesting property: **the authorization check is not bypassed**. It runs and returns a
correct answer about a different request. Anything built on "this path has an auth check" fails
silently and confidently. The fix is two lines, recording the error in `$matches` too plus a
re-entrancy guard.

**Reachability.** Core, on by default, unauthenticated, and no pretty permalinks needed since both
`/wp-json/batch/v1` and `/?rest_route=/batch/v1` answer. Cloudflare notes the path is reached
without a persistent object cache, which is not a meaningful filter since a default install has
none.

**Fixed in** 6.8.6 (CVE-2026-60137 only), 6.9.5, 7.0.2, 7.1 beta2, with forced auto-updates
enabled. All four prior WordPress entries in CISA KEV are plugins; pre-auth RCE in Core is
uncommon.

**Timeline.** On 17 July Searchlight withheld detail and Rapid7 reported no confirmed
exploitation. By 20 July the full breakdown was published, PoCs were circulating, and multiple
firms confirmed exploitation. Any advisory still saying "details withheld, no PoC" is now
distorting someone's prioritisation.

## Attribution

No actor has been publicly attributed as of 20 July, and I make no attribution claim.

- **H1, mass opportunistic scanning.** *Most likely.* Public PoCs within hours, no auth needed,
  large install base, honeypot activity consistent with indiscriminate scanning.
- **H2, access brokerage.** *Plausible.* Server-level access with database reach is more saleable
  than CMS defacement. Indistinguishable from H1 early, since divergence appears post-access and
  needs telemetry most affected sites lack.
- **H3, targeted use.** *Least likely, not dismissible.* Nothing favours targeting, but a
  peripheral site belonging to an organisation of interest is exposed on the same terms as
  everything else.

*Discriminators wanted:* uniformity of post-exploitation tooling, and whether exploitation follows
target-specific reconnaissance rather than broad scanning.

## Intelligence Gaps

1. **No public IOCs**, confirmed as of 20 July. Largest gap, and it propagates: it is why the IR
   guidance below is behavioural and why KJ-5 matters.
2. **Post-exploitation tradecraft.** Nothing on web shells, persistence, or infrastructure.
   Hexastrike has worked confirmed cases, so this may close soon.
3. **Volume and geography.** "Confirmed" is binary. No scan rates, nothing on Swiss or European
   hosting.
4. **Forced-update efficacy.** Unknown what share failed silently, which decides whether residual
   exposure lasts days or months.

## Outlook

**7 days.** *High:* continued broad scanning. *Moderate:* IOCs and post-exploitation reporting
emerge, closing Gaps 1 and 2. *Moderate:* KEV listing, which would be the first for Core.

**30 to 90 days.** *Moderate:* residual exposure dominated by silently failed or disabled
auto-updates. *Low:* absorption into commodity exploitation frameworks, low because I reason from
pattern rather than evidence.

**Longer term.** *Moderate:* renewed research on route confusion across other batch APIs, since
the defect (a security decision designed for once per request, made many times against parallel
state that must stay aligned) also exists in GraphQL, JSON-RPC, and vendor bulk endpoints.
*High:* AI-compressed exploit development keeps shortening patch windows, per KJ-2.

## Recommendations

**Asset and vulnerability management.** Patch, then *verify*, since forced auto-updates stall
silently on file-permission and disk problems. Enumerate every instance, including staging copies,
dead campaign microsites, departmental sites, and vendor-hosted sites on your domains. Per KJ-3,
version checking fails on hardened sites that strip the generator string; Hadrian published a
non-destructive probe that confirms the desync directly instead. If patching is blocked, keep
anonymous callers off the batch endpoint, and if using a WAF cover **both**
`/wp-json/batch/v1` and `?rest_route=/batch/v1`, since one alone leaves the site reachable.
Cloudflare has deployed rules for both CVEs on all plans including free.

**Detection.** Payload-based detection is weak here per KJ-3. The tractable signal is that
unauthenticated POSTs to the batch route are anomalous where the batch API is not used
anonymously. Template; field names depend on your proxy, and I would run it as a hunt first:

```kusto
let lookback = 30d;
CommonSecurityLog
| where TimeGenerated > ago(lookback)
| where isnotempty(RequestURL)
| where RequestURL has "batch/v1"
| where RequestMethod =~ "POST"
| summarize Requests = count(), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated),
            Statuses = make_set(DeviceCustomString1, 10),
            UserAgents = make_set(RequestClientApplication, 10)
    by SourceIP, DestinationHostName
| sort by Requests desc
```

The 30-day lookback is deliberate: the question is not only "is this happening now" but "did it
happen while we were unpatched", and retention closes that window regardless. Legitimate
authenticated batch traffic from the block editor is expected, so the discriminator is
authentication state and source, not payload.

**Incident response.** Patching does not answer whether compromise already happened, and per Gap 1
there are no indicators to check against. If an affected version was internet-facing after 17
July, assess behaviourally: unfamiliar or newly elevated admin accounts; recently modified PHP
under `wp-content/`, themes, and `mu-plugins/`; REST activity across the exposure window;
anomalous outbound connections; scheduled tasks, both WP-Cron and OS-level. On shared hosting,
scope beyond the single instance.

## Sources

Admiralty ratings are my own assessment.

| Source | Contribution | Rating |
|---|---|---|
| [Searchlight Cyber](https://slcyber.io/research-center/wp2shell-pre-authentication-rce-in-wordpress-core) | Disclosure, mitigations, technical breakdown | A1 |
| [Hadrian](https://hadrian.io/blog/wp2shell-a-pre-authentication-rce-in-wordpress-cores-rest-batch-api) | Root cause from patch, detection challenges, safe probe | A2 |
| [Tenable](https://www.tenable.com/blog/wp2shell-cve-2026-63030-cve-2026-60137-frequently-asked-questions-about-remote-code-execution) | CVSS, versions, exploitation status, KEV context | A1 |
| [Rapid7](https://www.rapid7.com/blog/post/etr-cve-2026-63030-wp2shell-a-critical-remote-code-execution-vulnerability-in-wordpress-core) | ETR, PoC prediction | A2, CVSS since superseded |
| Hexastrike, Patchstack | Exploitation confirmation | B2, via Tenable |
| Cloudflare | Object-cache note, WAF coverage | B2, via Tenable and Rapid7 |
| WordPress.org, GHSA-ff9f-jf42-662q, GHSA-fpp7-x2x2-2mjf | Versions, patches | A1 |

---

*Current as of 20 July 2026. Given the timeline above, treat anything here older than a few days
as needing revalidation. Judgments and detection guidance are mine; the vulnerability research
belongs to the credited researchers.*
