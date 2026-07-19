---
title: "I Deleted My Own Permissions and Became an Admin"
date: 2026-07-19
type: vdp
tags: [Web, Access Control, Privilege Escalation, VDP]
---

Another one from a vulnerability disclosure program. This time I had a test
account up front, a low-privilege user, a small step above guest, nothing
interesting attached to it.

And the application was clean. Genuinely clean. No XSS anywhere I looked, no
injection, no IDOR on the object identifiers I could reach, sensible session
handling. I spent a long time on it and had basically decided there was nothing
to find.

So in the last stretch, mostly out of boredom, I started doing things that made
no sense. One of them was removing my own role from my own account, which the
test user was allowed to do, which is already odd on its own.

I expected to be logged out, or locked into a permission-denied screen. Instead
I noticed I still had the user edit page in front of me. That shouldn't have
been true after stripping my own permissions, so I opened it again to see what
was left of it.

It wasn't reduced. It was expanded. With no role assigned, I could now grant
myself any role in the system, including system administrator. So I did.

The part that makes it a real finding rather than a curiosity is that it only
worked from that specific state. A plain guest account couldn't reach it,
because a guest couldn't remove a role it didn't have. You needed exactly the
sequence: start with a role, delete it, then walk back into the edit page in
the resulting state.

My guess at the cause is that the authorization logic compared my current role
against the role I was trying to assign, and with no role present that
comparison had nothing to fail on. The check wasn't absent, it just fell open
when the input it depended on disappeared. Nobody tests the roleless state
because in normal operation it can't happen, except here it could, because the
same application let a user delete their own role.

I wrote it up and sent it in. Their reaction was roughly the same as mine had
been: *huh?* It was fixed shortly after.

What I keep from this one is that the interesting states are usually the ones
nobody thought were reachable. Every permission check has an implicit
assumption behind it, and the fastest way to find where those assumptions break
is to put the account into a shape the developers never pictured (empty,
half-configured, mid-transition) and then repeat the same requests you already
tried.
