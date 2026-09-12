# Threat Model

## Security objective

SecureRepo should safely inspect an untrusted repository snapshot and produce useful evidence without executing repository code, exposing secret contents, escaping the intended filesystem scope through followed symlinks, or making unsupported security claims.

## Assets to protect

- developer and CI environment;
- repository confidentiality;
- credentials available to the caller;
- integrity of source files;
- integrity of generated reports;
- trustworthiness of SecureRepo findings.

## Primary threat actors / inputs

The scanner treats repository contents as potentially hostile. That includes intentionally crafted filenames, workflow text, directory layouts, symlinks, very large files, malformed encodings, and misleading configuration.

## Threat map

| Threat | Current V0.2 control | Residual risk |
|---|---|---|
| Secret values printed into reports | Sensitive-file rule is path/filename based and does not read contents | Other future content-based rules must preserve redaction |
| Symlink traversal outside repository | Recursive walker skips symlinks | Additional direct file reads must preserve this rule |
| Repository code execution | Scanner does not import or execute target repository code | Future plugins/install analysis could expand this surface |
| Network exfiltration | No runtime network dependency | Future CVE/provenance features will need explicit network policy |
| False security claim | Explicit assessment + coverage states and `PASS != SECURITY GUARANTEE` | Users can still misinterpret summaries |
| Parser ambiguity | GitHub Actions checks document line-oriented scope | Equivalent YAML may be missed |
| Resource exhaustion | Scanner avoids dependency installation and deep parsing | Very large directory trees can still consume time |
| Report path misuse | Output is explicit and separated from scan logic | Caller controls output location |
| Malicious filenames | Paths are represented as text and Markdown escaped where required | Terminal control-character handling needs future hardening |

## Safety invariants

SecureRepo V0.2 should maintain these invariants:

1. Do not execute repository code.
2. Do not install repository dependencies.
3. Do not follow symbolic links during recursive discovery.
4. Do not echo suspected secret-file contents.
5. Do not mutate scanned source files.
6. Do not claim unassessed capabilities passed.
7. Do not require network access for core scanning.
8. Treat malformed/unreadable inputs as evidence or reduced coverage, not silent PASS.

## Abuse and misuse boundaries

SecureRepo is intended for repositories the operator is authorized to inspect. It is a defensive static auditing utility, not an exploitation framework.

## Future hardening work

Before 1.0 the project should add:

- explicit file-count and file-size guardrails;
- terminal control-character sanitization;
- deterministic report ordering guarantees;
- fuzz/property tests for path and workflow inputs;
- Windows/Linux/macOS packaging tests;
- JSON schema validation;
- adversarial corpus tests;
- security review for any future network-enabled component.
