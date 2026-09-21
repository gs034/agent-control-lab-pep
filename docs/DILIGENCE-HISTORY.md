# Diligence history — residual GitHub PR refs

**Date:** 2026-09-21
**Repo:** Agent Control Lab PEP (`agent-control-lab-pep`)
**Brand:** Agent Control Lab only (Apache-2.0).

## Summary

The **default branch tip is clean** for Lab brand-wall purposes. A small set of **historical, GitHub-owned** pull-request refs still contain residual strings from an early scrub. Collaborators cannot delete `refs/pull/*` (GitHub returns read-only). This note discloses that fact for diligence readers. It is not a claim about attack success rates or product readiness.

## Verified facts (2026-09-21)

| Ref | Tip (short SHA) | Finding |
|-----|-----------------|---------|
| `main` | `634c2625bb53` | Clean — no residual legacy product-name tokens in the eval corpus tip tree |
| `refs/pull/1/head` | `4ab747a2dee7` | Historical tree still contains a Chinese-Wall keep-out line that named the residual token `AEGIS CapScope` |
| `refs/pull/2/head` | `cb28ce93bd7a` | Tree clean after scrub PR #2; immutable PR metadata still names that token in the branch name `cursor/scrub-aegis-capscope-eval-ca15` and in the scrub commit subject |

Scrub commit subject (PR #2): `chore(eval): scrub AEGIS CapScope wording for grant lock`

`DELETE` on `refs/pull/*` is rejected by GitHub (HTTP 422, read-only). Head branches for those names are already removed.

## Diligence reading

- Tip / release trees: treat as Lab-clean.
- Full-history / PR-ref scanners: expect the residual tokens above; they are disclosed here and are not present on current `main`.
- No repository recreate and no tip rewrite were performed for this disclosure.

## Related

Internal ring-fence memo (Lab vault): `ACL_Diligence_PR_Refs_Disclosure_2026-09-21.md`.
