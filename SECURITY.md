# Security Policy

## Supported Versions

Keyring has no tagged release yet. Once it does, security fixes go into the latest release.

## Reporting a Vulnerability

Please don't report a security problem in a public issue, pull request or discussion.

Report it privately through GitHub instead: open the repository's **Security** tab and choose **Report a vulnerability**, or go straight to [the form](https://github.com/entity/keyring/security/advisories/new). Only the maintainers see the report.

It helps to include:

- the Keyring version or commit, and your Laravel and PHP versions,
- the features and factors you have on, and your session driver,
- the steps to reproduce it, or a failing test,
- what someone could do with it.

## What Counts

[Security](docs/security.md) lists what Keyring guarantees. A way around one of those guarantees is a vulnerability, and so is anything that lets someone sign in, stay signed in or change an account when they shouldn't be able to.

The same page lists the [known limitations](docs/security.md#known-limitations). Those are documented behaviour, so an ordinary issue is the place for them.
