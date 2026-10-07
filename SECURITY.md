# Security and release hygiene

Never commit `.env`, API keys, access tokens, local databases, unselected result
directories, full logs, raw audit traces, backups, or recovery archives.
Only the de-identified, reviewed files under `reproducibility/revision_evidence/`
are intended for public result disclosure.

The adaptive-suite JSONL files contain synthetic malicious payloads and example
paths such as `/home/user/...`; they are inert test strings and are not executed
by the adaptive runner.

Before publication run:

```bash
python scripts/verify_public_package.py
python scripts/verify_revision_evidence.py
bash scripts/check_release_safety.sh
```


Upstream and release-specific files were reviewed to remove credentials,
machine-specific paths, and non-public artefacts.
