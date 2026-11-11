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

## How Soon We Act

Keyring is a small project, and these are the targets its maintainers hold themselves to, counted from when they learn of the problem:

| | Target |
|---|---|
| Answering a report | 3 working days |
| A fix or a workaround for a vulnerability in Keyring rated critical or high | 14 days |
| A fix for one rated medium or low | 60 days |
| Acting on a critical or high advisory in a dependency | 7 days |
| Acting on a medium or low advisory in a dependency | 30 days |
| Moving off a dependency version that no longer gets security fixes | 30 days after its support ends |

A fix ships in a new release, with a GitHub security advisory naming the versions affected. Until there's a tagged release, fixes go to `main`.

## Dependencies

Every pull request and every push to `main` runs `composer audit` on the PHP dependencies and `bun audit` on the browser package's, and both run again every week, since advisories come out between pushes. A known vulnerability fails the build.

Acting on an advisory means one of:

- raising the version Keyring requires, so the vulnerable ones can no longer be installed with it, and releasing that,
- replacing the dependency, when no fixed version is coming,
- saying in a security advisory why Keyring isn't affected, when the vulnerable code is something it never calls.

You don't have to wait for that. Keyring requires its dependencies by version range and ships no lock file, so `composer update` brings in a dependency's fixed release as soon as it's out. Run `composer audit` in your own app too: it covers Keyring's dependencies along with yours.

An abandoned package is listed by the audit without failing it. One that Keyring requires directly is replaced when a maintained alternative exists.

## What Counts

[Security](docs/security.md) lists what Keyring guarantees. A way around one of those guarantees is a vulnerability, and so is anything that lets someone sign in, stay signed in or change an account when they shouldn't be able to.

The same page lists the [known limitations](docs/security.md#known-limitations). Those are documented behaviour, so an ordinary issue is the place for them.
