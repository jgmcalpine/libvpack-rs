# Security Policy

## Project Status

V-PACK is under active development and should currently be considered experimental.

Unless explicitly stated otherwise in the project documentation, V-PACK has not received a complete independent security audit. It should not be relied upon as the sole mechanism for protecting funds, validating wallet state, or executing a unilateral exit involving funds that cannot safely be recovered by another tested method.

Security reports are nevertheless important during development, particularly where incorrect behavior could affect VTXO verification, transaction construction, or fund recovery.

## Supported Versions

Until V-PACK reaches a stable release, security fixes are normally applied only to:

| Version               | Supported |
| --------------------- | --------- |
| `main`                | Yes       |
| Latest tagged release | Yes       |
| Earlier releases      | No        |

Users of an affected earlier release may be required to upgrade to the latest release to receive a fix.

## Reporting a Vulnerability

Please do not open a public GitHub issue for a suspected security vulnerability.

Use GitHub's private vulnerability reporting feature:

1. Open the repository's **Security** section.
2. Select **Advisories**.
3. Select **Report a vulnerability**.

If private vulnerability reporting is unavailable, contact the maintainer through the private security contact identified in the repository documentation.

Please include as much of the following as possible:

* A description of the vulnerability.
* The affected commit, release, crate version, or feature.
* The potential security impact.
* Steps or test vectors that reproduce the issue.
* Any preconditions required to trigger it.
* Whether the issue is known to have been publicly disclosed or exploited.
* A suggested mitigation or patch, when available.

Do not include real seed phrases, private keys, wallet backups, authentication credentials, or other secrets in a report. Test vectors should use generated, non-production data.

## Security-Sensitive Issues

Examples of issues that should be reported privately include:

* Acceptance of invalid or malformed VTXO data, proofs, scripts, or transaction trees.
* Incorrect validation of Taproot commitments or spending conditions.
* Incorrect construction or validation of unilateral-exit transactions.
* Errors involving timelocks, sequence values, fees, sighashes, or transaction ordering.
* Reporting an output as recoverable when the generated recovery path cannot spend it.
* Differences between validation, visualization, and recovery results that could affect fund safety.
* Confusion between incompatible Ark transaction or VTXO formats.
* Exposure or unintended retention of secret key material or other sensitive wallet data.
* Panics, excessive memory usage, or excessive computation caused by untrusted input.
* Dependency or build-system vulnerabilities that could compromise V-PACK users.
* Any flaw that could materially mislead a user about ownership, spendability, expiry, or recovery of a VTXO.

This list is illustrative rather than exhaustive. When uncertain, report the issue privately.

## Issues That May Be Reported Publicly

The following can generally be reported through ordinary GitHub issues:

* Feature requests.
* Documentation improvements.
* Requests to support an additional Ark implementation or protocol dialect.
* Performance problems without a security impact.
* Clearly handled errors involving explicitly unsupported input.
* Test coverage and developer-experience improvements.

If a public issue is later found to have security implications, maintainers may temporarily remove or restrict it while the problem is investigated.

## Response Process

The project will make a reasonable effort to:

* Acknowledge a private report within five business days.
* Provide an initial assessment within ten business days.
* Keep the reporter informed while a confirmed vulnerability is being addressed.
* Coordinate public disclosure after a fix or adequate mitigation is available.

These are response targets rather than guaranteed remediation deadlines. Resolution time will depend on the severity and complexity of the issue.

Confirmed vulnerabilities may be handled through a GitHub repository security advisory. When appropriate, the advisory will identify affected versions, fixed versions, impact, mitigations, and reporter credit.

## Coordinated Disclosure

Please allow the maintainer a reasonable opportunity to investigate and address a vulnerability before publishing technical details.

The disclosure date will normally be coordinated with the reporter. Severe issues may require additional coordination with downstream wallets, Ark implementations, package maintainers, or users before complete details are published.

The project may publish an advisory before a complete fix exists when users need immediate mitigation guidance.

## Research Guidelines

Security research should:

* Use generated test data rather than real user funds or secrets.
* Avoid disrupting third-party systems or services.
* Avoid accessing data or funds belonging to another person.
* Stop testing and report the issue if testing could cause loss of funds or other harm.
* Comply with applicable laws and the policies of any external systems involved.

## Bug Bounties

V-PACK does not currently operate a paid bug-bounty program. Submission of a report does not create an entitlement to compensation.

## Credit

The project is happy to credit reporters in published advisories and release notes unless they prefer to remain anonymous.
