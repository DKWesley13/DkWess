# SBOM support

SecureRepo can generate a best-effort local CycloneDX 1.5 JSON inventory from selected dependency manifests.

```bash
dkwess-securerepo . --sbom reports/sbom.cdx.json
```

Version 0.0.7 currently extracts selected Python requirements / PEP 621 dependencies, npm package-lock entries, and Go module requirements using only Python's standard library.

The output is intentionally labeled as a **static manifest inventory**. It is not equivalent to a build-resolved or signed SBOM, may omit optional/transitive dependencies for unsupported formats, and does not query vulnerability services. Teams that need release attestations should combine SecureRepo evidence with their build system's authoritative SBOM/provenance process.
