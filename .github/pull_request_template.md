## Summary
Describe the problem and the change.

## Validation
- [ ] `python -m compileall -q src`
- [ ] unit tests pass
- [ ] SecureRepo self-audit passes
- [ ] documentation updated

## Security / trust-boundary impact
- Does this expand filesystem access?
- Add network access?
- Execute target code?
- Change GitHub token permissions?
- Add a runtime dependency?

## Rule-quality checklist
- [ ] stable rule ID
- [ ] severity/confidence justified
- [ ] remediation included
- [ ] positive and negative tests
- [ ] limitations documented
