---
title: "An SMS Endpoint That Trusted Everybody"
date: 2026-06-03
type: vdp
tags: [Web, Broken-Access-Control, SMS-Abuse, Bug-Bounty]
---
A phone-number verification endpoint — meant for an authenticated user adding a new number to their account — could be called without an account and without ever starting registration. From a logged-out browser, a single request triggered a real SMS to *any* number I supplied. A per-session retry cap existed, but it reset on navigation, leaving no meaningful brake on abuse. Class: Missing Authentication for a Critical Function (CWE-306) / Broken Access Control (OWASP A01:2021).

## The feature it was supposed to be

The endpoint — `/SmsAuthentication/SendCodeToNewNumber` — exists for a sensible reason: a logged-in user wants to add or change the phone number on their account, so the application sends a one-time code by SMS to prove they control the new number. Fine design. The problem is entirely about *who* is allowed to reach it.

## The bug

The endpoint performs a sensitive, real-world action — it makes the backend spend money and put a message on a stranger's phone — but it never checks that the caller is authenticated, or that the target number has anything to do with them. The "logged-in user updating their own number" context is assumed but never enforced. A short `fetch()` pasted into the dev console, with no session and without touching the registration flow, was enough to make the application send an SMS to an arbitrary, attacker-chosen number.

This is the textbook shape of broken access control: the real security control is the front-end flow, not the server. Skip the flow, call the endpoint directly, and the control is gone.

## The rate limit that wasn't

There *was* a brake — just not a useful one. The same call could be fired up to five times before the server returned a "maximum attempts reached" error. But the cap was tied to client-side session state rather than to the target number or the source: navigating back to the main page reset the counter, and the five-shot window reopened. Repeat indefinitely. A limit you can reset at will is a speed bump, and the SMS-flooding primitive survives it intact.

## Impact

Because no authentication is required and the destination number is attacker-controlled, this isn't "spam yourself" — it's directed at third parties:

- **Harassment / SMS bombing.** Messages delivered to a victim's phone they never asked for, trivially scripted.
- **Denial of wallet.** Every message is a billable SMS on the vendor's gateway — an unauthenticated cost-inflation attack at scale.
- **Brand and trust damage.** Messages arrive from a legitimate, recognized sender, causing confusion and giving useful raw material for later social engineering.
- **Zero barrier to entry.** No account, no email, no payment. The cost to launch is a console paste.

## Reproduction (high level)

Deliberately non-actionable — no working payload, target redacted.

```
1. Open the application logged out, without starting registration
2. Open the browser developer console
3. Issue one request to the new-number verification endpoint,
   supplying an arbitrary destination number as the parameter
4. Observe an SMS delivered to that number
5. Repeat to the per-session cap, then reload the main page
   to reset the counter and continue
```

## Root cause and fix

Two server-side assumptions, both wrong: authorization was inferred from UI context instead of enforced at the endpoint, and rate limiting was bound to client-side session state the attacker fully controls. The fix is to require an authenticated session and bind the action to that account server-side, then rate-limit on the destination number *and* source (IP / account / device) with limits that survive navigation. Add friction — CAPTCHA or proof-of-work — before anything triggers a billable SMS, and alert on send spikes per number as a backstop.

## Disclosure

Reported to the vendor through their security contact and kept anonymized here while a fix is pending. If you're doing the same kind of testing: stay inside your authorization, send the minimum number of messages needed to prove impact, and never point the destination at someone who didn't consent.
