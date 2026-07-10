---
title: "Detecting ClearFake with KQL, Mapped to ATT&CK"
date: 2026-07-10
type: research
tags: [KQL, Detection-Engineering, ClearFake, MITRE-ATTACK, Defender]
---
The companion post to this one ends on an uncomfortable fact: the blockchain leg of an EtherHiding delivery can't be taken down, because the payload lives in an immutable smart contract. You block the transport where you can, but some fetches will always slip a static list. So the real detection has to sit on the endpoint, watching for what the attack *does* rather than where it comes from. This is how I built that detection for a ClearFake / ClickFix chain in KQL, and — just as importantly — how I decided what to key on and what to leave alone.

## The detection hypothesis

ClearFake's chain has a lot of moving parts, but only some of them are worth detecting. The blockchain read is invisible to endpoint tooling. The compromised website isn't mine to monitor. What *is* visible, and what every variant of this attack shares, is the moment a human is tricked into running a command: a browser leads to an overlay, the overlay tells the user to paste something into a terminal, and an interpreter runs. That user-driven execution is the choke point. The hypothesis is simply: *a browser should not be the thing that leads to `powershell.exe` running a download-and-execute one-liner.*

## The kill chain, mapped to ATT&CK

Before writing a single query it helps to lay the chain against ATT&CK, because it tells you where the detectable techniques actually are:

- **T1189 — Drive-by Compromise:** the visitor hits a compromised site.
- **T1059.007 — JavaScript:** the injected loader.
- **T1102 — Web Service:** the on-chain retrieval (the closest fit — see below).
- **T1204 — User Execution:** the ClickFix lure; the user runs the command themselves.
- **T1059.001 — PowerShell:** the pasted command executes.
- **T1140 — Deobfuscate/Decode:** the payload is unpacked in memory.
- **T1105 — Ingress Tool Transfer:** the next stage is pulled down.

Two things stand out. First, the on-chain retrieval has *no clean ATT&CK technique* — "Web Service" is the nearest match, but it was written with Twitter-and-Pastebin dead-drops in mind, not immutable smart contracts. That gap is itself worth noting in a report. Second, the highest-signal, most durable technique in the list is **T1204 → T1059.001**: the user-executed interpreter. That's where I aimed.

## Choosing the detection surface

The infrastructure indicators — the C2 domains, the RPC hosts — are real and worth having, but they decay. Domains rotate, and the RPC hosts are shared public infrastructure that everything on the chain touches. If I anchor only on those, the rule goes blind the moment the operator registers a new domain. The *behaviour* — browser spawns interpreter, interpreter runs a download cradle — doesn't rotate, because it's the part the social-engineering depends on. So I built two layers: precise infrastructure rules for what I've already seen, and one behavioural rule that survives rotation.

## Rule 1 — known C2 (Stage 4)

Straight indicator match on the C2 domains and the path marker observed in the case. High-fidelity, but it only catches known infrastructure:

```
let c2 = dynamic(["dntds.shop","sdntds.shop"]);
DeviceNetworkEvents
| where RemoteUrl has_any (c2)
    or (RemoteUrl has "/teamrepo")
| project Timestamp, DeviceName, InitiatingProcessFileName,
          RemoteUrl, RemoteIP, ActionType
| sort by Timestamp desc
```

## Rule 2 — the behavioural backstop

No indicators at all. This is the one that still fires when the domains change, because it keys on the ClickFix execution pattern itself — a browser as the parent of an interpreter running a download-and-execute command:

```
let browsers = dynamic(["chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe"]);
let interps  = dynamic(["powershell.exe","pwsh.exe","mshta.exe","cmd.exe","wscript.exe","cscript.exe"]);
DeviceProcessEvents
| where InitiatingProcessFileName in~ (browsers)
| where FileName in~ (interps)
| where ProcessCommandLine has_any ("iex","invoke-expression","irm","invoke-restmethod",
        "downloadstring","frombase64string","-enc","-encodedcommand",
        "-w hidden","windowstyle hidden","mshta ")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName,
          FileName, ProcessCommandLine
| sort by Timestamp desc
```

## Rule 3 — the on-chain leg (Stage 2)

The retrieval, matched on the RPC hosts seen in the case. A word of caution belongs right next to it: these are legitimate, shared public BSC-testnet nodes, so raw RPC hits are noise-prone. This query earns its place only in combination with browser context (which it filters on) or the contract address — never on its own:

```
let rpc = dynamic(["bsc-testnet-rpc.publicnode.com",
  "bsc-testnet.bnbchain.org","bsc-testnet.drpc.org",
  "data-seed-prebsc-1-s1.bnbchain.org"]);
DeviceNetworkEvents
| where RemoteUrl has_any (rpc)
| where InitiatingProcessFileName in~ ("chrome.exe","msedge.exe","firefox.exe")
| project Timestamp, DeviceName, RemoteUrl, RemoteIP,
          InitiatingProcessFileName
| sort by Timestamp desc
```

## The one thing the endpoint can't see

The cleanest anchor of all would be the smart-contract address and the function selector — those are the truly stable part of the delivery. But they live inside the JSON-RPC request body, sent over HTTPS. Endpoint network telemetry sees the hostname, not the POST body, so the contract address never appears in `DeviceNetworkEvents`. Unless you have a TLS-inspecting proxy that logs request bodies, the contract stays a threat-intel and hunting pivot, not something you can write an EDR rule against. Worth being honest about that in a report rather than implying a detection you can't actually field.

## Tuning out the noise

Rule 1 and Rule 3 are naturally tight. Rule 2 is the one that needs baselining, because a browser legitimately spawning PowerShell isn't unheard of — some admin tooling, some enterprise apps launched from a browser context, some developer workflows. The move is to profile what that looks like in your own estate first, then allowlist by signer or path rather than loosening the command-line terms. Cutting false positives by trusting a signed binary is safe; cutting them by removing `downloadstring` from the match blinds the rule. As with any triage, the goal is a rule an analyst can trust every line of.

## Validating it

You don't need the real sample to prove these fire. The T1204 → T1059.001 behaviour is trivially reproducible in a lab: launch a browser, have it spawn `powershell.exe` with a benign `iex`-style command line, and confirm Rule 2 alerts with the right process lineage. Atomic Red Team has tests in the same shape. Validate the lineage and the command-line match, not the payload.

## Limitations and layering

One rule is never coverage. Rule 1 goes quiet on domain rotation; Rule 2 depends on the interpreter actually being a child of the browser (a lure that instructs Win+R rather than a pasted terminal command changes the parent); Rule 3 is deliberately noisy on its own. The blockchain leg has no clean signature at all from the endpoint. Treat these as a layered set — infrastructure for precision, behaviour for durability — and keep the contract address in your TI platform as the pivot that ties incidents together across all of them.

## Takeaway

The instinct with a chain this novel is to chase the exotic part — the blockchain. But the blockchain is the one link you can neither block nor see from the endpoint, so it's the wrong thing to build a detection around. The durable, catchable moment is the oldest trick in the chain: a human pasting a command they were told to trust. Anchor there, keep the infrastructure indicators as a precise-but-perishable layer on top, and be upfront about the one indicator — the contract — that lives somewhere your sensors can't reach.
