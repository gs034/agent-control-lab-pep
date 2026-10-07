# Mutation audit 2026-10-07-impl

- PEP commit: `95cf2c666f00e26348d2f7e8d78d42b42cd00656`
- Python: 3.12.3
- Mutants specified by: other-family
- Timeout per run: 300.0 s

The kill rate is reported as measured. There is no pass threshold.

## Kill rate

- Timeouts counted as killed: 10 of 10 (100%)
- Timeouts not counted as killed: 10 of 10 (100%)

Outcomes: killed 10, survived-never-activated 0, survived-oracle-masked 0, timeout 0, invalid 0, harness-fault 0. Invalid patches (0) and harness faults (0) are outside the denominator.

## Mutants

| Mutant | File | Activation | Intent | Property attacked | Outcome | Killing tests | Seconds |
| --- | --- | --- | --- | --- | --- | --- | --- |
| M01 | `pep/implementation.py` | `open_executable:162` | Skip F_ADD_SEALS so the memfd copy is never write-sealed after fchmod. | ADR-0005 Decision §1.3 / acceptance 'no seal': the copy must be sealed (F_SEAL_WRITE\|GROW\|SHRINK\|SEAL) so it cannot change after digest. | killed | `tests/test_execute_digested.py::test_the_sealed_copy_refuses_write_grow_and_shrink` | 4.7 |
| M02 | `pep/implementation.py` | `167`, `168`, `169`, `171`, `172` | Digest the on-disk file after copy instead of reading back the sealed memfd. | ADR-0005 Decision §2 / acceptance 'digest from disk instead of the copy': digest must be of the sealed copy, not the path on disk. | killed | `tests/test_execute_digested.py::test_bytes_added_to_the_memfd_before_sealing_are_digested`<br>`tests/test_execute_digested.py::test_file_rewritten_after_the_copy_is_not_what_gets_digested` | 3.96 |
| M03 | `pep/implementation.py` | `163`, `164`, `165` | On seal failure, close the memfd and fall back to an on-disk O_RDONLY fd instead of raising. | ADR-0005 Decision §6 / acceptance 'path fallback on failure': open_executable must raise ImplementationUnavailable and never fall back to the path/disk artefact. | killed | `tests/test_execute_digested.py::test_refused_fchmod_is_unavailable_and_closes_the_memfd` | 4.2 |
| M04 | `pep/implementation.py` | `98` | Use caller pass_fds as the whole set (defaulting to the handle) instead of merging the handle into the caller set. | ADR-0005 Decision §3 / acceptance 'pass_fds replaced instead of merged': caller pass_fds must be merged with the sealed-copy fd, not replaced. | killed | `tests/test_execute_digested.py::test_caller_pass_fds_are_kept_alongside_the_handle` | 4.14 |
| M05 | `pep/implementation.py` | `95` | Stop refusing executable= so subprocess can exec a different binary than the sealed copy. | ADR-0005 Decision §3 / acceptance 'executable= passed through'; run docstring: executable= is refused because it can run something other than the copy. | killed | `tests/test_execute_digested.py::test_run_refuses_shell_and_executable[executable]` | 4.29 |
| M06 | `pep/implementation.py` | `241` | On EINVAL from memfd_create with MFD_EXEC, raise instead of retrying without MFD_EXEC. | ADR-0005 Decision §1.2 / acceptance 'the MFD_EXEC retry removed': pre-6.3 kernels reject MFD_EXEC with EINVAL and the helper must retry without it. | killed | `tests/test_execute_digested.py::test_kernel_without_mfd_exec_falls_back_and_still_works` | 3.82 |
| M07 | `pep/implementation.py` | `101`, `104`, `106` | Build argv from real_path strings instead of /proc/self/fd sealed paths. | ADR-0005 Decision §3–4 and module docstring: run must exec the sealed copy via /proc/self/fd so nothing is resolved by path after the copy. | killed | `tests/test_execute_digested.py::test_in_place_write_after_open_runs_the_digested_program`<br>`tests/test_execute_digested.py::test_file_rewritten_after_the_copy_is_not_what_gets_digested`<br>`tests/test_execute_digested.py::test_pinned_interpreter_runs_under_a_combined_digest` | 3.96 |
| M08 | `pep/implementation.py` | `95` | Stop refusing preexec_fn= so the caller can run arbitrary code in the child before exec. | ADR-0005 Decision §3 and run docstring: preexec_fn= is refused because it can run something other than the copy. | killed | `tests/test_execute_digested.py::test_run_refuses_shell_and_executable[preexec_fn]` | 4.2 |
| M09 | `pep/implementation.py` | `_open_regular:229` | Drop the regular-file check so a FIFO or other non-regular PATH hit is opened and copied. | ADR-0005 Decision §1.2 / open_executable docstring: a source that is not a regular file is refused (O_NONBLOCK open alone is not enough). | killed | `tests/test_execute_digested.py::test_a_fifo_on_path_is_refused_without_hanging` | 3.99 |
| M10 | `pep/implementation.py` | `160`, `161`, `162`, `168` | Compute the digest before fchmod/seals so bytes written through the fd after digest and before seal are what run. | ADR-0005 Decision §2: digest is read back over the whole sealed file after sealing, so bytes present when sealed match the digest. | killed | `tests/test_execute_digested.py::test_bytes_added_to_the_memfd_before_sealing_are_digested` | 3.83 |

## Survivors

None.
