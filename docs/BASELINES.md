# Known-findings baselines

SecureRepo baselines support gradual adoption without pretending existing findings are fixed.

Create a baseline:

```bash
dkwess-securerepo . --write-baseline .securerepo-baseline.json
```

Compare a later scan:

```bash
dkwess-securerepo . --compare-baseline .securerepo-baseline.json
```

Gate only new HIGH-or-higher findings:

```bash
dkwess-securerepo . \
  --compare-baseline .securerepo-baseline.json \
  --fail-on HIGH \
  --fail-on-new
```

`--fail-on-new` returns exit code `4` when a new finding reaches the selected threshold. Known findings remain visible in the normal audit report. A baseline is not an allowlist and never converts a finding into `PASS`.

## Fingerprints

Baselines use the stable finding fingerprint produced from rule ID, path and title. This is intentionally simple and deterministic. A material path/rule/title change may therefore appear as one resolved finding plus one new finding.

## Review guidance

Commit a baseline only when the team has reviewed its contents. Do not use baselines to conceal critical issues. Resolve known findings over time and regenerate the baseline deliberately when the accepted snapshot changes.
