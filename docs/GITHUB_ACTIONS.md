# GitHub Actions integration

SecureRepo includes a root `action.yml` composite action.

## Recommended posture
Pin every external action to a reviewed immutable commit SHA and use minimal permissions.

```yaml
name: Repository audit

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  securerepo:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<FULL_COMMIT_SHA>
        with:
          persist-credentials: false

      - name: SecureRepo audit
        uses: DKWesley13/DkWess@<FULL_SECURE_REPO_COMMIT_SHA>
        with:
          path: .
          output: reports
          fail-on: HIGH
          require-full-coverage: "false"
```

Replace placeholders with reviewed full commit SHAs.

## Inputs
| Input | Default | Meaning |
|---|---|---|
| `path` | `.` | repository path |
| `output` | `reports` | report directory |
| `fail-on` | `HIGH` | finding threshold |
| `require-full-coverage` | `false` | require all capability coverage to be FULL |

Pinning creates a stronger identity/review boundary but does not prove an action is safe.

## Licensing caveat
The source is public, but a software license has not yet been selected. Public visibility is not a general grant of reuse/redistribution rights; the composite action is best considered an evaluation/integration preview until the license is selected.

SecureRepo writes reports but does not upload artifacts automatically, keeping its permissions and behavior small.
