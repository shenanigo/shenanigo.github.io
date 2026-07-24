---
title: "A Token Is Not a Rate Limit"
date: 2026-07-24
type: vdp
tags: [Web, Enumeration, Information Disclosure, Disclosure]
---

Everyone checks the login form and the password reset for username enumeration.
The account reactivation flow ... the one that wakes a dormant account back
up ... almost never gets the same look, even though it's wired into the same
identity backend as everything else. I'm writing this one up because of how
little it took to turn it into an oracle, and because the underlying mistake
... a response that changes depending on who you ask about ... is everywhere.

The flow itself is simple. You submit a username, and if that account is
dormant it lets you start reactivating it. The problem was in what it did with
usernames that weren't dormant.

Feed it something that isn't a real account and it tells you the username is
unknown. Feed it a real account that's currently active and it tells you the
account isn't deactivated. Feed it a real account that actually is dormant and
it moves you straight on to the next step. Three inputs, three visibly
different answers (the wording paraphrased here). From outside, with no session
at all, that's enough to sort any username into doesn't-exist, active, or
dormant.

That's more than plain username enumeration. A normal existence oracle leaks
one bit ... real or not. This one leaked account state on top of it (CWE-204,
observable response discrepancy). And the state is the part that stings: a
dormant account is the one nobody's watching, whose owner won't notice a
reactivation attempt, and which is the most likely to still be sitting on a
weak or reused password. A flow that points at its own dormant accounts is
handing over a target list.

Underneath it, the form had no meaningful brute-force protection. I could
repeat the same invalid guess as often as I liked, no throttling, no lockout,
no challenge. On its own that's a finding. Combined with an oracle that tells
valid from invalid, it's the front half of a password-spraying run. There was a
smaller embarrassment too: a generic, default-looking username resolved to a
live account.

It's worth being precise about the one control that was present, because it's
the kind of thing that gets logged as a mitigating factor when it isn't one.
The reactivation request carries an anti-CSRF token, and at a glance that looks
like it takes automation off the table ... you can't just capture one request
body and fire it a thousand times. But the token is sitting right there in the
returned HTML, in a named form field, readable by anything that fetches the
page. And it isn't even spent after a single use ... one token was good for a
run of submissions, on the order of ten, before it rotated. So the real cost of
working around it is roughly one page fetch per batch of guesses: request the
page, read the token out of the markup, reuse it until it's exhausted, fetch
another. The same-origin policy stops a page on *another* origin from reading
that token, which is exactly what the token is for and it does that job fine.
But a script talking to the endpoint directly isn't a cross-origin browser and
isn't bound by any of that. So the token stops cross-site request forgery,
which is what it's for, and does effectively nothing to slow enumeration ... a
real rate limit counts requests, and this one waved ten of them through per
token.

That distinction matters, because the tempting move is to note "there's an
anti-CSRF token" and quietly knock the severity down a notch. It isn't a
mitigating factor here. The bug was never that the request replays ... it's that
the response changes with the account behind it, and a control the caller can
simply read for itself was never going to fix that. Mistaking "there's a token"
for "this can't be automated" is exactly how response oracles survive a test.

None of this needed a list of usernames to prove. One request with a value I
knew was invalid, one against my own account, and the difference between the two
responses is the whole finding. Sweeping real users would have added no
evidence, just other people's account states sitting in my notes for no reason
... so I didn't. I reported it through the program with those two
request/response pairs and a description of the three states. I've left out the
organisation, the endpoint and the real response wording here, and I kept
nothing beyond my own test requests.

The lesson is the same shape as most enumeration bugs: an authentication flow
should answer the same way regardless of which account is behind the input.
Exists or not, active or dormant ... one neutral response, one code path. The
moment a reactivation, unlock or resend-confirmation endpoint starts varying its
reply by account state, it has stopped being a login helper and become an
oracle.
