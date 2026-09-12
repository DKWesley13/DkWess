# Supply-chain and provenance evidence

Version 0.0.5 adds local, static supply-chain inventory and provenance evidence.

```bash
dkwess-securerepo . \
  --supply-chain reports/supply-chain.json \
  --provenance reports/provenance.json
```

The supply-chain inventory lists recognized manifests plus external GitHub Actions and Docker action references. It records whether supported action references are immutable.

The provenance report records locally available Git origin/HEAD evidence and detected manifests. Credentials, URL query strings and fragments are removed from URL-style origins before reporting.

These reports deliberately do **not** query vulnerability databases, execute package managers, verify remote signatures, or claim remote authenticity. They are evidence inputs for review, not a complete software-supply-chain attestation.
