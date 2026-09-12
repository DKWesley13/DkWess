# SARIF output

SecureRepo can export findings as SARIF 2.1.0 for tools that consume static-analysis results.

```bash
dkwess-securerepo . --sarif reports/securerepo.sarif
```

The SARIF output includes rule metadata, severity-derived SARIF levels, file/line locations when available, remediation text, and SecureRepo finding fingerprints.

For GitHub Code Scanning, use a trusted upload workflow with minimum permissions and pin third-party actions to reviewed immutable commit SHAs. SecureRepo generates SARIF but does not silently upload data or request network access.

SARIF is another representation of the implemented checks; it does not expand scanner coverage. `PASS != SECURITY GUARANTEE` still applies.
