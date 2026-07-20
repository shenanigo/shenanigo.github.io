---
title: "The URI Chokepoint: Hunting Cobalt Strike Beacons in Proxy Logs"
date: 2026-07-20
type: research
tags: [detection-engineering, kql, cobalt-strike, threat-hunting, c2]
---

# The URI Chokepoint: Hunting Cobalt Strike Beacons in Proxy Logs

Most Cobalt Strike detection content focuses on the parts of the tool that are hardest to
change: default TLS certificates, named pipe patterns, stager URI checksums, sleep-mask
artefacts in memory. Those work, but they age badly. Operators patch them out, and the
publicly circulated cracked builds get progressively more sanitised.

This post is about a weaker-looking indicator that turns out to be more durable, because it
comes from an architectural decision rather than a default value: **a beacon uses exactly one
GET URI and one POST URI for its entire lifetime.**

Credit where it belongs, the core observation and the original KQL are from Mehmet Ergene's
post [Detecting Cobalt Strike HTTP(S) Beacons with a Simple
Method](https://academy.bluraven.io/blog/detecting-cobalt-strike-https-beacons-with-simple-method)
at Blu Raven Academy. What follows is my reading of *why* it works, what breaks when you move
it into a Microsoft Sentinel environment, and where I think the tuning knobs actually are.

## The mechanism

Malleable C2 profiles are the reason Cobalt Strike survived as long as it did as a red team
tool. The profile controls HTTP method, headers, user agent, cookie handling, body encoding,
and the request URIs, so a beacon can be dressed up as anything from a CDN callback to an
Office 365 telemetry ping.

The `http-get` and `http-post` blocks both accept a *list* of URIs. Intuitively you would
expect a beacon to rotate through them, that is what a list is for, and it is what most
people assume when they first read a profile. It does not. The beacon selects one URI from
the GET list and one from the POST list, and then uses those two for every subsequent
check-in. There is no rotation.

Ergene also notes that while public profiles conventionally use different URIs for GET and
POST, there does not appear to be a strict requirement that they differ. So the practical
floor is not two URIs per destination, it is one.

That is the chokepoint. A beacon calling home every 60 seconds for a working day produces
hundreds of requests to a single host, spread across at most two distinct paths. Very little
legitimate software behaves that way. Browsers pull dozens of paths per origin. API clients
usually hit several endpoints. Even a narrowly scoped telemetry agent tends to accumulate
query-string variation, and, crucially, is normally installed on more than one machine.

The signal is not "one URI." It is **one URI, high request volume, low host prevalence**, all
three together.

## The original query

Ergene's query runs in two passes. The first builds a candidate set of destinations, the
second joins back for enrichment:

```kusto
let whitelisted_hosts = dynamic(["add-hosts-after-initial-analysis"]);
let lookback = 1d;
let susp_hosts =
OPNsense_CL
| where TimeGenerated > ago(lookback)
| where destination_hostname_s !in (whitelisted_hosts)
| extend RequestURI = tostring(parse_url(url_original_s).Path)
| where isnotempty(RequestURI)
| summarize dcount(RequestURI), prevalence = dcount(source_ip_s) by destination_hostname_s
| where dcount_RequestURI <= 2 and prevalence <= 4
;
susp_hosts
| join hint.strategy=shuffle kind=inner (
    OPNsense_CL
    | where TimeGenerated > ago(lookback)
    | extend RequestURI = tostring(parse_url(url_original_s).Path)
    | where isnotempty(RequestURI)
    | project TimeGenerated, source_ip_s, RequestURI, destination_hostname_s,
              http_request_method_s, http_request_bytes_d, http_response_bytes_d
) on destination_hostname_s
| summarize hint.shufflekey=source_ip_s count(), dcount(http_request_bytes_d),
            dcount(http_response_bytes_d), make_set(destination_hostname_s)
            by RequestURI, http_request_method_s, source_ip_s, bin(TimeGenerated, 1d)
| where count_ >= 300
| sort by TimeGenerated, count_ desc
```

Three things worth pulling out of that.

The whitelist sits at the top and is explicitly labelled to be filled in *after* initial
analysis. That is the correct sequencing and it is worth resisting the urge to pre-populate
it. If you allowlist before you have looked, you will allowlist the thing you were hunting
for.

`prevalence` is defined as distinct source IPs per destination, not request count. This is
the piece doing the real work. A one-URI destination that fifty hosts talk to is a badly
designed SaaS endpoint. A one-URI destination that one host talks to is worth a look.

The byte-count `dcount`s in the final summarize are not filters, they are triage aids.
Uniform request and response sizes are a beacon tell; wildly varying sizes suggest actual data
transfer. You read those columns, you do not threshold on them, at least not until you know
your own baseline.

## Porting it to Sentinel

The source table is `OPNsense_CL`, a custom log. Ergene flags that you need to change table
and field names for your own environment. That is a bigger caveat than it sounds, and it is
worth being specific about where it bites.

**You need the path, not just the hostname.** The entire method is built on
`parse_url(...).Path`. For HTTPS traffic without TLS inspection, your proxy sees a CONNECT to
a hostname and nothing more. Every destination collapses to zero distinct URIs and the query
returns either everything or nothing depending on how your `isnotempty` filter lands. Before
writing a line of KQL, confirm you are actually logging full request URLs for HTTPS. If you
are not, this technique does not apply to that traffic and no amount of tuning will fix it.

**Candidate tables, in rough order of usefulness:**

- `CommonSecurityLog`, CEF from most proxy and NGFW vendors. `RequestURL`,
  `DestinationHostName`, `SourceIP`, `RequestMethod`, `SentBytes`, `ReceivedBytes`. Usually
  the best fit, since the schema maps almost field-for-field.
- A vendor-specific `_CL` table, Zscaler, Squid, whatever you run. Same shape, different
  names.
- `DeviceNetworkEvents` from Defender for Endpoint, has `RemoteUrl`, but populated
  inconsistently depending on the connection type, and it is not a proxy log. Useful as a
  secondary pivot to attach a process and a device name to a hit, weak as the primary
  detection source.

A `CommonSecurityLog` translation of the first pass:

```kusto
let whitelisted_hosts = dynamic(["add-hosts-after-initial-analysis"]);
let lookback = 1d;
CommonSecurityLog
| where TimeGenerated > ago(lookback)
| where isnotempty(RequestURL)
| where DestinationHostName !in (whitelisted_hosts)
| extend RequestURI = tostring(parse_url(RequestURL).Path)
| where isnotempty(RequestURI) and RequestURI != "/"
| summarize UniqueURIs = dcount(RequestURI), Prevalence = dcount(SourceIP)
    by DestinationHostName
| where UniqueURIs <= 2 and Prevalence <= 4
```

Note the added `RequestURI != "/"` filter. Bare-root requests are extremely common in
legitimate traffic, health checks, redirects, link previews, certificate validation, and in
my view they will dominate your candidate set otherwise. A beacon *can* of course use `/`, so
this is a trade: you accept a blind spot in exchange for a workable result volume. If you have
the budget to review the noise, drop the filter.

## Where the thresholds bend

The two numbers in the original query are the ones you will spend your time on. Neither is
wrong; both encode assumptions about environment size and beacon configuration that may not
hold for you.

**`prevalence <= 4`** assumes a small-to-mid estate. In a large environment, four distinct
source IPs is a tight ceiling that will discard genuine single-host beacons the moment
anything else in the estate touches the same destination, a security tool doing URL
reputation lookups, a proxy health probe, a curious analyst. Prevalence is really a proxy for
"is this destination normal here", and distinct source count is a crude way to measure it.
If you have the data, a rarity calculation against a longer baseline window is more honest
than a fixed integer against 24 hours.

**`count_ >= 300`** is the one I would watch hardest. Three hundred requests in a one-day bin
implies a beacon checking in roughly every five minutes at most, and realistically far more
often. That is a fine assumption for a noisy commodity intrusion. It is a poor assumption for
a patient operator: a beacon on a 30-minute sleep with 30% jitter will produce well under a
hundred requests a day and fall straight through this floor. The same applies to the `bin(..., 1d)`
grouping, which quietly rewards short sleeps.

If you build this out, parameterise both. My instinct is to run it as two queries with
different profiles rather than one compromise, an aggressive high-volume pass on a short
lookback for commodity activity, and a patient low-volume pass on a much longer window where
you lean harder on prevalence and accept that you will read more results by hand. The second
one is not an alert. It is a monthly hunt.

## Honest limitations

Ergene states two, and they matter:

1. **Cobalt Strike ≥ 4.10 supports updating host and URI configuration** at runtime. An
   operator on a current licensed build can move the goalposts.
2. **External / user-defined C2 is not covered at all.** If the beacon is not speaking the
   built-in HTTP(S) profile, none of this applies.

His argument for why it remains useful is that the cracked builds circulating in the wild are
predominantly 4.5 and 4.9. I think that is a fair read of the commodity end of the threat
landscape, and it is worth being clear about what it implies: this is a technique aimed at
ransomware affiliates and lower-tier intrusions using pirated tooling, not at a well-resourced
actor with a current licence. That is not a criticism. Most of what actually walks through the
door is the former.

I would add a third limitation of my own. The method has no concept of *what the traffic is* —
it is a shape detector. It will flag a beacon and it will equally flag an obscure single-purpose
internal integration that nobody documented. That is acceptable for a hunt, where a human reads
the output, and it is a problem for an alert rule, where nobody does. My view is that this
belongs in the hunting queries library rather than as an analytics rule, at least until the
whitelist has matured over several iterations.

## What to do with it

The sequence I would follow:

1. Confirm your proxy logs contain full request paths for HTTPS. If not, stop here.
2. Run the first pass alone, no join, no volume floor. Look at the raw candidate list. This
   tells you what your environment's baseline weirdness looks like before you tune anything.
3. Populate the whitelist from that review, deliberately, one entry at a time, with a reason
   recorded for each.
4. Add the join and the volume filter. Adjust `prevalence` and `count_` to your estate size
   rather than inheriting them.
5. Pivot any hit into endpoint telemetry to attach a process and a signer to the connection.
   The proxy tells you a shape; the endpoint tells you whether it is a beacon.

The broader lesson is the one worth keeping. The strongest detections are rarely built on
defaults, because defaults are the first thing an operator changes. They are built on
constraints the tool's architecture imposes on the operator whether they like it or not.
Malleable C2 gives an operator enormous freedom over what the traffic looks like, and almost
none over how many distinct URIs it uses.

---

**Source:** Mehmet Ergene, [*Detecting Cobalt Strike HTTP(S) Beacons with a Simple
Method*](https://academy.bluraven.io/blog/detecting-cobalt-strike-https-beacons-with-simple-method),
Blu Raven Academy. The technique and the original KQL are his; the Sentinel adaptation,
threshold analysis, and commentary above are mine.
