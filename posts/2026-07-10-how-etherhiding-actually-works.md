---
title: "How EtherHiding Actually Works"
date: 2026-07-10
type: research
tags: [EtherHiding, ClearFake, Blockchain, Malware, Threat-Intel]
---
Most malware needs somewhere to live. A server, a bucket, a bulletproof host — some box with an IP and usually a domain in front of it. That's also its weakness: once a defender finds the address, they block it, and once law enforcement finds the host, they seize it. EtherHiding is the attacker's answer to that problem. Instead of a server you can take down, the payload lives inside a public blockchain — and there's nothing to seize. I ran into it while pulling apart a compromised WordPress site, and the mechanics are worth understanding properly, because the usual "just block the C2" reflex doesn't map cleanly onto it.

## The problem it solves (for the attacker)

Every takedown in the traditional model targets a physical thing: an IP to null-route, a domain to sinkhole, a host whose provider will pull the plug after an abuse report. Bulletproof hosting buys the attacker time, but it's still a location, and locations can be blocked.

EtherHiding removes the location. The payload is stored as data inside a smart contract on a public chain — most commonly BNB Smart Chain (BSC), sometimes Ethereum, and in some campaigns the BSC *testnet*, where the transactions cost nothing at all. Once that contract is deployed, it's immutable and ownerless. There's no provider to send an abuse report to, no server to image, no domain registrar to lean on. The malware's "hosting" is now a decentralised ledger replicated across thousands of nodes.

## A 60-second blockchain primer for defenders

You don't need to care about crypto to follow this. Two facts are enough.

First, a smart contract is just code and data sitting at an address on the chain, and you can stuff arbitrary strings into its storage. That string can be a blob of JavaScript.

Second — and this is the part that makes the technique work — you can *read* that storage without writing anything. Blockchains distinguish between transactions (which change state, cost gas, and are permanently recorded) and calls (which only read state). The read path uses an RPC method called `eth_call`. It creates no transaction, costs nothing, and leaves no entry in the chain's transaction history. The attacker writes the payload once; every victim after that just reads it, invisibly.

## The mechanism, step by step

Put together, the chain of events looks like this:

1. The attacker compromises a legitimate website — very often WordPress — and injects a small loader script into the page.
2. When a visitor loads the page, that loader makes a read-only `eth_call` to a specific contract address on BSC or Ethereum.
3. The contract returns the next-stage payload as a string — typically more JavaScript.
4. The loader executes it in the victim's browser.

The injected loader is tiny and generic; the interesting logic lives on-chain, out of reach. Because the fetch is a plain read, there's no on-chain footprint pointing back to the operator, and the payload can be swapped at any time by sending a single new transaction — every compromised site then serves the new version automatically, with no need to touch the sites again.

## Why it's so resilient

Three properties stack up in the attacker's favour. There's no domain or IP that *hosts* the payload, so classic blocklisting has nothing to bite. The operator can rotate the payload centrally and instantly. And the whole thing is cheap — reads are free, and on testnet even the initial write is free. Researchers at Guardio Labs, who named the technique in 2023, framed it as exactly this: takedown-resistant, decentralised hosting that shifts the economics firmly toward the attacker.

## Where it sits in a real kill chain

EtherHiding is a delivery layer, not a payload, so it shows up as one link in a larger chain. The one I analysed followed the pattern that's become typical: a compromised WordPress site injects the loader, the loader pulls its next stage off the chain, and that stage renders a **ClickFix** lure — a fake browser-update or verification overlay that socially engineers the user into pasting a command into their own terminal. The command runs an infostealer. The blockchain never touches disk; it's purely the resilient delivery pipe in the middle. (I pulled the on-chain loader apart in [The Malware That Hid on a Blockchain] if you want the deobfuscation detail.)

## From crimeware to nation-state

What makes EtherHiding worth a writeup in 2026 rather than 2023 is how far up the food chain it's travelled. It started in the financially motivated ClearFake campaign. Then Google's Threat Intelligence Group and others documented a financially motivated cluster (tracked as UNC5142) using it to turn many thousands of legitimate WordPress sites into a distribution network, pushing infostealers that decrypt and run entirely in memory to dodge disk-based detection.

The bigger shift came when GTIG reported a North Korean actor (UNC5342) adopting the technique — by their account the first time a nation-state had been seen using it. That campaign uses the blockchain to stage a JavaScript downloader which in turn fetches an in-memory espionage implant, and notably reaches the chain through centralised API providers rather than public RPC nodes, which makes the traffic blend in further. A technique that began as a crimeware hosting trick is now in the toolkit of state-sponsored operators — which is usually the signal that a delivery method has proven itself.

## Can't you just block it? Transport vs. storage

This is the question a sharp reader asks immediately, and the answer is more useful than a flat "no." The trick is to separate two different objects.

The **contract** is *storage*. It's immutable and ownerless — genuinely takedown-resistant. Nothing you or a registrar or a police force can do removes it.

The **RPC or API endpoint** the browser calls is *transport*. And transport is an ordinary HTTPS host. The victim's browser can't commune with the chain by magic — it has to reach a node's hostname to make that `eth_call`. Block that hostname at your egress and the read fails: no stage payload comes back, the ClickFix overlay never renders, the user is never prompted, and the follow-on host is never reached. You break the chain upstream, by cutting transport, without ever touching the storage you can't remove.

In practice this is a strong, cheap control, because **most managed environments have no legitimate reason for a workstation to talk to a blockchain RPC node at all**. In a network like that, default-deny egress with no crypto/Web3 category permitted neuters this entire class of delivery at near-zero collateral. It should be the first thing you reach for.

It's a first line, though, not a silver bullet. RPC endpoints rotate; there are many public ones and anyone can stand up more, so a static list is whack-a-mole. Worse, an attacker can front the call through a generic centralised API provider — as the nation-state cluster above did — or proxy it through their own innocuous-looking domain, which is far harder to enumerate than an obvious `bsc-*` host. But transport is also exactly where cooperative pressure works: when researchers reported the abuse to the responsible API providers, several acted quickly (others didn't). So you block what you can at the edge, and you accept that some fetches will slip a static list — which is precisely why the endpoint is the place to catch what the network missed.

## Takeaway

EtherHiding isn't magic, and it isn't unstoppable — it's a clean separation of concerns that happens to favour the attacker. The payload lives somewhere you can't take down, but it can only reach a victim through transport you *can* block and behaviour you *can* detect. Get the payload out of your head as the thing to chase; it's immutable and it doesn't care about you. Cut the RPC path at egress where you have no legitimate Web3 traffic, and catch the ClickFix execution on the endpoint for everything else. The companion post walks through building that endpoint detection in KQL.
