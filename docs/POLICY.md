# Policy engine

Version 0.0.8 adds explicit TOML/JSON policy support.

```bash
dkwess-securerepo . --policy securerepo.toml
```

Example:

```toml
[policy]
fail_on = "HIGH"
require_full_coverage = false
disabled_rules = []
exclude_paths = ["tests/fixtures/*"]
allow_critical_suppression = false
```

CLI `--fail-on` overrides the policy threshold. `--require-full-coverage` can make the policy stricter for a particular run.

Suppressions are counted and surfaced in CLI/JSON policy-application metadata. They do not prove a finding is safe. SecureRepo refuses to disable a CRITICAL rule unless `allow_critical_suppression = true` is explicitly set.

Path exclusions use shell-style glob matching against normalized repository-relative finding paths. Keep policies narrow, review changes to them like code, and do not use them to turn unknown risk into a misleading green status.
