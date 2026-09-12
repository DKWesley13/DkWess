# SecureRepo usage cookbook

## Basic audit

```bash
dkwess-securerepo /path/to/repository
```

## CI threshold

```bash
dkwess-securerepo . --fail-on MEDIUM
```

## Strict implemented coverage

```bash
dkwess-securerepo . --require-full-coverage
```

## Explain rules

```bash
dkwess-securerepo --list-checks
dkwess-securerepo --explain SR-GHA-010
```

## Known-finding regression gate

```bash
dkwess-securerepo . --write-baseline .securerepo-baseline.json
dkwess-securerepo . --compare-baseline .securerepo-baseline.json --fail-on HIGH --fail-on-new
```

## Policy

```bash
dkwess-securerepo . --policy securerepo.toml
```

## Evidence bundle

```bash
dkwess-securerepo . \
  --output reports \
  --supply-chain reports/supply-chain.json \
  --provenance reports/provenance.json \
  --sarif reports/securerepo.sarif \
  --sbom reports/sbom.cdx.json
```

## Machine-readable stdout

```bash
dkwess-securerepo . --json-stdout --no-reports
```

## Resource bounds

```bash
dkwess-securerepo --show-limits
```

## v1 release-readiness check

```bash
dkwess-securerepo . --release-check
```

Exit codes: `0` selected gates passed, `1` runtime/config error, `2` severity threshold, `3` incomplete implemented coverage, `4` new baseline regression, `5` technical release-readiness blocker.
