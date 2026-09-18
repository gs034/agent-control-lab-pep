# Contributing (Agent Control Lab)

This repository is a public-goods, Apache-2.0 **Agent Control Lab** host/runtime PEP stub. Contributions must stay Lab-only.

## Accept

- Lab-branded PEP, eval fixtures, threat model, and security notes already in this tree.
- Diligence docs that do not invent attack-success metrics or weaken the fail-closed deny path.
- Apache-2.0 SPDX on first-party Python.

## Reject

- Commercial product, bank, or marketplace adapters and live git hosts.
- Production SaaS UI.
- Brand strings, SKU language, and source trees from commercial or bank lines. CI enforces the keep-out list (`scripts/check_lab_only.sh`, workflow `lab-only` / job `forbidden-tokens`; also `scripts/lab_brand_wall.py`). Do not add those tokens to files, diffs, commit subjects, or branch names.
- Acquisition-origin notices or other-product catalogue language.

If the brand wall fails, remove the hit. Do not add a bypass in first-party docs.

## How to test

```bash
python -m pip install -e ".[dev]"
python -m pep.demo
pytest
bash scripts/check_lab_only.sh
python3 scripts/lab_brand_wall.py
```

The Lab-only keep-out is stdlib Python (`scripts/lab_brand_wall.py`; `scripts/check_lab_only.sh` is a wrapper). Ripgrep is not required.
