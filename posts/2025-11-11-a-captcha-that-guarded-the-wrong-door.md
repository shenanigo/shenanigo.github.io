---
title: "A CAPTCHA That Guarded the Wrong Door"
date: 2025-11-11
type: research
tags: [Web, Broken-Access-Control, CAPTCHA, SMS-Abuse]
---
During account registration, a "resend verification code" endpoint — `/ResendSms` — would send an SMS to *any* number an attacker specified, not the number actually entered during registration. A CAPTCHA guards the start of the registration flow, but once inside a registration session the resend action trusts attacker-supplied input and fires real SMS. The registration data itself is never verified: any pattern-valid email and phone number is accepted. Class: Broken Access Control / business logic (≈ CWE-639) plus Improper Control of Interaction Frequency (CWE-799).

## The setup

Registration starts the way you'd expect: enter an email and phone number, accept the terms and privacy policy, solve a CAPTCHA. Two things matter. First, none of the registration data is verified at this stage — the email and phone only need to match a valid *format*, so any throwaway, pattern-valid values are accepted. Second, the CAPTCHA sits at the entrance; solving it lets you proceed. The natural assumption is that this gate protects whatever comes next. It doesn't.

## The bug

Inside the registration session, the application exposes a "resend code" endpoint so a user who didn't receive their SMS can ask for another. Reasonable feature. The problem: `/ResendSms` sends to a number supplied in the request, and never enforces that this number matches the one tied to the in-progress registration. Hand it an arbitrary number and it sends there. "Resend my code" has quietly become "send a code to anyone I choose."

This is the same broken-access-control failure as a missing auth check, one layer in: the server makes an authorization-relevant decision — who should receive this SMS — from attacker-controlled input instead of trusted session state.

## Why the CAPTCHA doesn't save you

A CAPTCHA is a one-time challenge at the door. But the dangerous action — sending an SMS to an attacker-chosen number — is repeatable, and the CAPTCHA isn't re-presented per send. In the environment I tested, one solved registration session let the resend fire up to five times before a "maximum attempts reached" error.

Re-arming is cheap: navigate back to the main page, re-run registration with fresh throwaway data, solve the CAPTCHA again, and you have another batch of five. The challenge raises the cost per batch slightly — but CAPTCHAs are routinely outsourced or automated, the registration data is disposable, and the limit counts per session rather than per destination number. Nothing actually caps how many messages a victim's phone receives. The gate guards entry to the building while the valuable thing sits unlocked in the lobby.

## Impact

- **Harassment / SMS bombing.** An attacker-supplied victim number receives messages in batches, scriptable around the CAPTCHA.
- **Denial of wallet.** Each message is a billable SMS; the per-session cap doesn't bound total cost because sessions are free to recreate.
- **No identity required.** Throwaway, unverified email and phone get you in; nothing ties the abuse to a real account.
- **A false sense of protection.** The presence of a CAPTCHA can make this path *look* defended in a quick review — exactly why it's worth calling out.

A higher-friction route than a fully unauthenticated one, but "higher friction" isn't "mitigated" when the friction is a re-solvable challenge and a resettable counter.

## Reproduction (high level)

Deliberately non-actionable — no working payload, target redacted.

```
1. Start registration with throwaway but pattern-valid email and phone
2. Accept terms, solve the CAPTCHA to enter the registration session
3. Issue a resend request specifying an arbitrary destination number
4. Observe an SMS delivered to that number
5. Repeat to the per-session cap, then restart registration with
   fresh throwaway data to re-arm
```

## Root cause and fix

The resend endpoint authorizes by trusting a number in the request, and the rate limit counts something the attacker can recreate at will.

- **Bind the destination server-side.** A resend should target only the number associated with the in-progress registration session — from server state, never the request body.
- **Rate-limit on what you're protecting.** Key limits on the destination number and source (IP / device), enforced across sessions and restarts, with global ceilings per number per time window.
- **Don't let a one-time CAPTCHA stand in for ongoing control.** A challenge at the entrance does nothing for a repeatable action behind it — gate the action, re-challenge, or both.
- **Add cost to disposable registrations** so throwaway data can't be cycled freely.

## Disclosure

Reported to the vendor through their security contact and kept anonymized here while a fix is pending. Same rules as always: stay inside your authorization, send the minimum needed to prove impact, and never aim the destination at someone who didn't consent.

## Takeaway

Controls get evaluated by where they sit, not by whether they're present. A CAPTCHA, a login wall, a rate limit — each only protects the exact boundary it's placed on. Here the boundary was the front door, while the action that actually cost money and reached strangers lived just inside it, trusting whatever number it was handed. The question to ask of your own apps isn't "is there a control?" but "is the control on the thing that's dangerous?"
