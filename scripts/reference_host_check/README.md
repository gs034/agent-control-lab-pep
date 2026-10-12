# Live check of the reference host deployment

`live_check.py` runs the reference host the way the README tells an operator
to run it, and tries each written claim from the agent side. The claims come
from [ADR-0007](../../docs/adr/ADR-0007-reference-host-process.md), the
"Reference host under its own user" section of the README, and
[ADR-0008](../../docs/adr/ADR-0008-reference-host-deployment-acceptance.md).

It runs real operating-system users, a real Unix socket, a real halt file and
a real decision log. Each claim prints PASS or FAIL, and the exit status is 1
if any claim fails.

## Run it

Linux, as root, with Python 3.11 or later. It needs `runuser` and `setpriv`
(util-linux). It creates two users if they are missing, `acl-pep` (the host)
and `acl-agent` (the agent, in group `acl-agent`), and it uses test paths
`/var/lib/acl-pep-check` and `/run/acl-pep-check`.

```bash
sudo python3 scripts/reference_host_check/live_check.py --source .
```

It takes about a minute. The host is started and stopped by the script, and
nothing is left running afterwards.

## What it does not prove

- It runs one host configuration: the built-in stub policy, the echo tool,
  and the default limits. A different policy file or registry is not covered.
- It does not test an agent that runs as the host user, or that can write the
  host's directories. ADR-0007 states that those attacks defeat the separation.
- It does not test kernel or LSM behaviour beyond what it observes on this
  machine, or any platform other than Linux.
- Its timing claims (idle 5 seconds, deadline 30 seconds, window 1 second) are
  checked with real waits, so a loaded machine can make a timing claim fail
  without the host being wrong. Re-run before concluding anything from one
  failure.

## Checking the checker

The check was run against three seeded faults in a scratch copy of the code.
Each was caught by the claim it breaks:

- a peer allow-list that accepts every peer: "a peer outside --allow-uid is refused" fails;
- a connection cap of 64 instead of 8: "a ninth connection is refused" fails;
- a decision log created with mode 0644: the host refuses to start, and every scenario fails.
