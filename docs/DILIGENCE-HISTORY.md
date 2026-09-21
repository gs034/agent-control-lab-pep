# Diligence history — residual GitHub PR refs

**Date:** 2026-09-21  
**Repo:** Agent Control Lab PEP ()  
**Brand:** Agent Control Lab only (Apache-2.0).

## Summary

The **default branch tip is clean** for Lab brand-wall purposes. A small set of **historical, GitHub-owned** pull-request refs still contain residual strings from an early scrub. Collaborators cannot delete  (GitHub returns read-only). This note discloses that fact for diligence readers. It is not a claim about attack success rates or product readiness.

## Verified facts (2026-09-21)

| Ref | Tip (short SHA) | Finding |
|-----|-----------------|---------|
|  |  | Clean — no residual legacy product-name tokens in the eval corpus tip tree |
|  |  | Historical tree still contains a Chinese-Wall keep-out line that named the residual token  |
|  |  | Tree clean after scrub PR #2; immutable PR metadata still names that token in the branch name  and in the scrub commit subject |

Scrub commit subject (PR #2): 

 on  is rejected by GitHub (HTTP 422, read-only). Head branches for those names are already removed.

## Diligence reading

- Tip / release trees: treat as Lab-clean.
- Full-history / PR-ref scanners: expect the residual tokens above; they are disclosed here and are not present on current .
- No repository recreate and no tip rewrite were performed for this disclosure.

## Related

Internal ring-fence memo (Lab vault): .
