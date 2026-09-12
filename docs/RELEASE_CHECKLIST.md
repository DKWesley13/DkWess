# Release checklist

## Source state
- [ ] release commit identified
- [ ] changelog updated
- [ ] package version and `__version__` match
- [ ] README version badge matches

## Validation
- [ ] compile source
- [ ] unit tests pass
- [ ] version/list-checks smoke checks pass
- [ ] SecureRepo self-audit passes at intended threshold
- [ ] JSON report valid
- [ ] documentation examples match CLI

## Security
- [ ] no credentials/private data in diff
- [ ] no unexpected runtime dependency
- [ ] workflow permissions reviewed
- [ ] remote actions pinned where used
- [ ] security docs current
- [ ] known HIGH/CRITICAL regressions reviewed

## Public readiness
- [ ] clean-environment install tested
- [ ] license status explicit
- [ ] support path documented
- [ ] breaking changes documented

## Stable 1.0 additional gates
- [ ] license selected
- [ ] cross-platform validation complete
- [ ] stable schema policy
- [ ] adversarial corpus complete
- [ ] release evidence packet complete
