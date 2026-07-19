---
title: "The Password Didn't Matter"
date: 2026-07-19
type: research
tags: [Web, IDOR, Access Control, Disclosure]
---

This one is from a while back, at an organisation I'm no longer with. It's not
a sophisticated bug. I'm writing it up because of how little effort it took,
and because the underlying mistake is everywhere.

The setup: an internal web portal where you log in with your own account and
see your own stuff ... timetable, grades, absences, personal details.

Usernames were five-digit numbers. Passwords were a fixed three-letter prefix
followed by four digits, and the prefix was the same for every account. So the
guessable part of anyone's password was four digits, and the login form had no
rate limiting and no lockout at all. Ten thousand tries, unlimited attempts.

Finding valid usernames wasn't hard either, because the timetable page put them
straight in the URL:

```
https://<portal>/timetable/12345
```

Increment, get a different person. That's the whole enumeration technique.

But I never actually needed to brute-force anything, because there was a bigger
problem underneath.

I was logged in as myself, poking at requests in Burp, and noticed that the
request to load my profile page included my own five-digit ID as a parameter.
So I changed it to someone else's and forwarded it. The server sent back their
profile. Grades, absence history, personal details, all of it. And it wasn't
just reading ... the absence-reporting function behaved the same way, so I could
have submitted absences under their name.

That's IDOR (CWE-639, OWASP A01). The application checked that I had a valid
session, which was true, and then never checked whether that session actually
owned the record it was being asked to return. It verified who I was at login
and then trusted whatever ID I claimed afterwards.

What sticks with me is how the pieces reinforced each other. Sequential IDs in
the URL meant the user list was public. The password template meant the
keyspace was tiny. No brute-force protection meant that tiny keyspace was
actually usable. Any one of those is a finding you'd write up on its own. But
the missing ownership check made all of them irrelevant, because you didn't
need credentials for a second account at all ... your own session was enough.

I reported it internally with a description of the request manipulation and
what data was reachable. It was fixed not long after. I've left out the
organisation, the real URL structure and the password prefix here, and I didn't
keep anything beyond my own test requests.

The lesson isn't complicated: a session tells you who is asking, not what
they're allowed to have. If an endpoint takes an object ID from the client, it
needs to check ownership server-side on every single request. And if you want
to find this kind of thing yourself, the method is dull but reliable ... log in
as yourself, watch which identifiers your own session is sending, and change
one.
