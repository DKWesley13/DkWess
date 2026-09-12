# Security Policy

## Supported versions

DkWess SecureRepo is currently in early V1 development. Security fixes are applied to the latest code on `main` until the project begins publishing tagged releases.

## Reporting a vulnerability

Please do not publish exploit details, credentials, private data, or customer information in a public issue.

For a suspected vulnerability, contact the maintainer through an appropriate private channel available on the maintainer's GitHub profile. Include a concise description, affected component, reproducible conditions, and impact. Do not include real secrets or unrelated personal data.

## Scope

The project is a static repository hygiene and governance scanner. Findings are evidence for review, not proof that a repository is secure or insecure in every respect.

A SecureRepo `PASS` means only that none of the implemented checks produced findings at the configured threshold for the scanned snapshot.

`PASS != SECURITY GUARANTEE`

## Safe testing

Please test against repositories and systems you are authorized to assess. The project does not require destructive testing, credential use, or active exploitation.
