# Live check of the reference host deployment

`live_check.py` runs the reference host the way the README tells an operator
to run it, and tries each claim in the table in
[ADR-0008](../../docs/adr/ADR-0008-reference-host-deployment-acceptance.md)
from the agent side. The claims come from
[ADR-0007](../../docs/adr/ADR-0007-reference-host-process.md), the
"Reference host under its own user" section of the README, and ADR-0008.

It runs real operating-system users, a real Unix socket, a real halt file and
a real decision log. Each claim prints PASS or FAIL, and the exit status is 1
if any claim fails.

## Run it

Linux, as root, with Python 3.11.4 or later. It needs `runuser`, `setpriv` and
`install` (util-linux and coreutils). It creates two users if they are missing,
`acl-pep` (the host) and `acl-agent` (the agent, in group `acl-agent`), and it
uses test paths `/var/lib/acl-pep-check` and `/run/acl-pep-check`.

> **Do not run this on a shared or production host.** It creates the system
> users `acl-pep` and `acl-agent` and deletes its test directories as root.
> Without `--yes` it prints what it would do and exits with status 2.

```bash
sudo python3 scripts/reference_host_check/live_check.py --source . --yes --cleanup \
  --allow-uid "$(id -u acl-agent)" --allow-gid "$(id -g acl-agent)"
```

`--allow-uid` and `--allow-gid` are the agent user's ids. The check passes
both to every host it starts. The claim that a peer outside the list is
refused uses a different user id and this same group id. Omitting the flags
still uses the `acl-agent` user the check creates. A value that is not that
user is refused.

`--cleanup` removes the users, the group and the test directories at the end,
but only the users and group that this run created. The check only deletes a
directory under `/opt/acl-pep-check`, `/var/lib/acl-pep-check`,
`/run/acl-pep-check`, or a `--scratch-root` you name (at least two levels
deep). A symlink at one of those paths is refused. The damaged halt file is
written as the host user with `O_NOFOLLOW`, so root never writes, chowns or
chmods by path inside a directory the host user owns.

It takes about a minute. The host is started and stopped by the script, and
nothing is left running afterwards.

## What it does not prove

- It runs one host configuration: the built-in stub policy, the echo tool,
  and the default limits. A different policy file or registry is not covered.
- It does not test an agent that runs as the host user, or that can write the
  host's directories. ADR-0007 states that those attacks defeat the separation.
- It does not test kernel or LSM behaviour beyond what it observes on this
  machine, or any platform other than Linux.
- Timing is measured with real waits. The idle close is accepted between 4 and
  8 seconds, and the deadline close between 28 and 36 seconds. A loaded machine
  can push a measurement outside those bounds without the host being wrong, so
  re-run before concluding anything from one failure. The one-second
  coalescing window is not timed, and neither is the 30-denials-per-window cap.

## Checking the checker

Each of these faults was made in a scratch copy of the code and run against the
final harness. Each one fails the claim it breaks:

- a peer allow-list that accepts every peer: "a peer outside --allow-uid is refused" fails;
- a connection cap of 64 instead of 8: "a ninth connection is refused" fails;
- a depth cap of 100000 instead of 32: "JSON nested deeper than 32" fails;
- a size cap of 10 MB instead of 64KiB: "a request over 64KiB" fails;
- a decision log created with mode 0644: the host refuses to start. The
  host-start checks fail, and the socket-directory startup check fails with the
  log message. The state-directory startup check still passes, because that
  refusal happens before the log is opened, so it is not a sign the check is weak.
