---
title: "Nevermind, I'm Already Systemadmin"
date: 2026-07-19
type: vdp
tags: [Web, API, Authentication, VDP]
---

Also from a while back. This one is my favourite finding so far, mostly because
of the timing.

I was testing a web application under a vulnerability disclosure program (VDP). As an
unauthenticated user I couldn't get anywhere, I poked at it for a good while
and came up with nothing worth reporting. The program offered test accounts on
request, so I opened a ticket and asked for one.

Then, maybe two minutes later, I went back to their Swagger interface, which
was publicly exposed, and started reading through the endpoint list properly
instead of skimming it.

One of them was called something like `testAsUser`. It took a single parameter,
`Role`. And according to the spec, it required no authentication.

So I opened Postman and started guessing role names. `user`, `admin`,
`superadmin`, the usual list. Most of them came back with errors. Then I
fat-fingered one and typed `administratorr`, with the extra `r`.

That one returned a JWT.

I dropped the token into localStorage, refreshed the app, and I was a system
administrator. Full permissions, no credentials, no account, nothing but a
public endpoint and a typo.

The typo is the part I still enjoy. `administratorr` wasn't clever guessing on
my part, it was a mistake that happened to match a mistake on theirs. The role
string had been misspelled somewhere in their code, so the correctly spelled
version didn't exist and mine did.

At that point I went back to the ticket I'd opened a few minutes earlier and
cancelled it, with the comment: *nevermind, don't need the user anymore, I'm
already systemadmin.*

The phone rang inside of five minutes.

The explanation was the boring one it usually is. The endpoint had been built
for debugging during development, was never meant to reach production, and
nobody removed it. It got pulled shortly after I reported it, and I got some
nice recognition for the find.

Two things I took away from it. First, exposed API documentation is not just
recon, it's a list of things the developers forgot they shipped, read every
entry, including the ones with dull names. Second, if an endpoint hands out
tokens, the security of it cannot rest on nobody knowing the right string to
send. Debug helpers need to be gated by build configuration or removed
entirely, not hidden behind a parameter value.

And sometimes it isn't skill. Sometimes you just misspell the same word the
developer did.
