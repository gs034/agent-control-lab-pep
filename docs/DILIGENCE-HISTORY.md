# Diligence history — residual historical PR refs

**Date:** 2026-09-22
**Repo:** Agent Control Lab PEP (`agent-control-lab-pep`)
**Brand:** Agent Control Lab only (Apache-2.0).

## Summary

The current `main` tip is Lab-clean for brand-wall purposes. Residual keep-out strings are legacy commercial product-name tokens. They are documented in the Lab chinese-wall vault and are not spelled in this tree. They remain only on GitHub-owned historical pull-request refs and associated PR metadata, not on the current `main` tip tree.

Pull requests #1 and #2 were merged historically. Collaborators cannot delete `refs/pull/*` (GitHub returns HTTP 422, read-only). **Support/GC is the only path to purge `refs/pull/*`.**

This note is a diligence disclosure. It is not a claim about attack success rates or product readiness. No history rewrite and no repository recreate were performed.

## Verified refs (2026-09-22)

SHAs below were checked against the live GitHub pull refs. Findings name the ref and SHA only.

| Ref | SHA | Residual location |
| --- | --- | --- |
| `main` | `1d0f3809a4a16d4a6ac3524b287cf719f192e1f9` | None in the tip tree |
| `refs/pull/1/head` | `4ab747a2dee710b86039b30a50a756b68e50065b` | Historical ref tree (merged PR #1). PR metadata for #1 does not carry the strings |
| `refs/pull/2/head` | `cb28ce93bd7ab6c49ee7ecbf62d9a35290e62771` | PR metadata for merged PR #2: the head branch name, and the commit subject stored on this SHA. That ref's tree does not contain the strings |

The token strings themselves are recorded only in the Lab chinese-wall vault memo `agent-control-lab/ring-fence/ACL_Diligence_PR_Refs_Disclosure_2026-09-21.md`.

## Purge path

Do not attempt to delete `refs/pull/*` with a collaborator credential. GitHub treats those refs as read-only (HTTP 422). Support/GC is the only path to purge `refs/pull/*`.

## Reading guide

- Tip and release trees: treat as Lab-clean.
- Full-history or PR-ref scanners: expect residual legacy commercial product-name tokens on the historical SHAs above. They are not on current `main`.
- Do not copy those strings into tip files, commit subjects, or branch names.

An earlier public draft (pull request #8, tip `4a3bfb392a3c6d3b01a5e49a430ca66983a78598`) named the residual strings in-repo and was closed unmerged. This note does not repeat them.
