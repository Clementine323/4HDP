# Security and release hygiene

Never commit `.env`, API keys, access tokens, local databases, result
directories, full logs, raw audit traces, backups, or recovery archives.

The adaptive-suite JSONL files contain synthetic malicious payloads and example
paths such as `/home/user/...`; they are inert test strings and are not executed
by the adaptive runner.

Before publication run:

```bash
python scripts/verify_public_package.py
bash scripts/check_release_safety.sh
```


Upstream and release-specific files were reviewed to remove credentials,
machine-specific paths, and non-public artefacts.
