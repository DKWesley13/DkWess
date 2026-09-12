# FAQ and troubleshooting

## Does PASS mean my repository is secure?
No. `PASS != SECURITY GUARANTEE`.

## Does SecureRepo upload my source code?
The current scanner is local-first and contains no source-upload logic. It reads local files and writes local reports.

## Does it read my secrets?
Sensitive-filename checks use names/paths and do not read or print matched contents. Other capabilities read limited text configuration such as `.gitignore` and workflow YAML because those configurations are what is being analyzed.

## Why is GitHub Actions NOT_ASSESSED / UNKNOWN?
Usually because there are no `.github/workflows/*.yml` or `.yaml` files. That is not PASS.

## Why REVIEW_REQUIRED with no HIGH finding?
LOW, MEDIUM, INFO findings or BLOCKED capabilities still deserve review even if the configured exit threshold stays green.

## Why did strict coverage return 3?
At least one capability had PARTIAL or UNKNOWN coverage.

## Why is `.npmrc` flagged if it has no token?
It is credential-adjacent and may be harmless. SecureRepo intentionally asks for review instead of claiming it definitely contains a secret.

## Why flag `@v4`?
Tags can move; a full commit SHA provides stronger immutability.

## Why flag `pull_request_target`?
It runs in base-repository context and needs careful separation from untrusted pull-request code.

## Can this replace a full security review?
No.

## Command not found after installation
Try `python -m dkwess_securerepo --version`. If that works, virtual-environment activation/PATH is likely the issue.

## Is the project open source already?
The repository is public, but an explicit software license has not yet been selected. That remains a separate maintainer decision.
