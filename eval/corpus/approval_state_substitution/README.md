# Approval state substitution

Existence-proof DENY only. Not an attack-success-rate claim.

The operator mints a single-use approval for `echo.ping` with exact args and
freezes a host-computed state digest of the object the invoke acts on. The
later envelope carries the same tool and args but the host observes a
different state digest: the target changed between approval and execute.
`try_consume` returns `approval_state_mismatch` and does not consume the
grant. Threat pattern: Loopjacking-class post-approval state substitution
(arXiv:2609.21081, pattern name only). The companion ALLOW row
`allow_approval_state_bound` shows an identically bound grant consumed when the
observed digest matches.
