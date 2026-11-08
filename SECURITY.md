# Security Policy

## Supported versions

The latest release. Older versions get no fixes: if you are on one, the answer to a
vulnerability is to upgrade.

## Reporting a vulnerability

**Do not open a public issue.**

Use GitHub's **private vulnerability reporting** on this repository: the *Report a
vulnerability* button under the Security tab. It opens a thread only you and the
maintainer can see.

If that is not available to you, email **rogerj@gmail.com** with `prefixbrowser` in the
subject line.

## What a report must contain

- **Where.** The function and line in `nbprefix.py`, and the version or commit.
- **What the code actually does there**, not what a name suggests it does.
- **Why that is wrong**, as a concrete consequence: what an attacker gets, and under
  what conditions.
- **How to see it.** A reproduction or a precise sequence of steps. If it cannot be
  reproduced, say so and describe what you did observe.

## Reports produced with AI assistance

Use whatever tools you like to find a problem, but **a person must have checked the
finding against this code before it is sent, and must be able to answer questions
about it.** A report that reads as unreviewed generated text (no line, code quoted
that does not exist here, a reproduction that does not run) is closed without analysis.
If you did use a tool, say so; that is not held against you.

## What to expect

This is a spare-time project with a single maintainer. **There is no guaranteed
response time.** The answer will be a fix, a documented limitation, or an explanation
of why the behaviour is not what it appears to be. You will be credited unless you ask
not to be.

## Scope

`nbprefix` runs locally on the user's own PC, serves a web page on `127.0.0.1`, and only
reads from NetBox. In scope is what this code does:

- the local web server: who can reach it, what it answers, and what another web page
  open in the same browser can make it do
- the API token: where it is sent, and whether it can leak through the page, the
  local API or error messages
- TLS to NetBox, and how data from NetBox is rendered in the page

**Not in scope:** flaws in NetBox, Python or the browser (report those upstream, but an
issue saying this tool is exposed to one is welcome), and the documented limitations:
the token is stored in plain text in `nbprefix.json` on the user's PC, and
`"verify_tls": false` turns certificate checks off.
