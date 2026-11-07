# Repudiation Resolver

A local transaction journal for investigating disputes through signed receipts,
append-only records and independently verifiable evidence. Transactions are simulated;
no real payments are processed.

## Features

- Server-enforced administrator, operator and viewer roles.
- Amount-limit decisions with recorded reasons and policy versions.
- Ed25519 signatures, SHA-256 hash chains and simulated timestamp attestations.
- Filtered, paginated event history with popup evidence inspection.
- Evidence export, uploaded-file verification and an independent CLI verifier.
- Signer revocation with a separate operational audit trail.

## Requirements

- Node.js 24 or newer, npm, and Git.
- An installed Chrome, Chromium or Brave browser for optional browser tests.

SQLite is supplied by Node.js. No separate database service or Docker is required.

## Setup

From the project directory:

```bash
npm ci --ignore-scripts
npm test
```

Create local accounts before signing in. There is no public signup or default password.
Choose separate passwords of **12–128 characters** and replace the placeholders below.

Linux, macOS or Git Bash:

```bash
INIT_PASSWORD='<administrator-password>' npm run init -- administrator admin
INIT_PASSWORD='<operator-password>' npm run init -- analyst operator
INIT_PASSWORD='<viewer-password>' npm run init -- observer viewer
```

PowerShell, for example:

```powershell
$env:INIT_PASSWORD = '<administrator-password>'
npm run init -- administrator admin
Remove-Item Env:INIT_PASSWORD
```

Repeat with the other usernames/roles if needed. Existing usernames cannot be created twice.

Start the application:

```bash
npm start
```

Open **http://127.0.0.1:3000** and sign in using a local account. Interactive API
documentation is available at **http://127.0.0.1:3000/docs/**.
After backend code changes, restart the server and refresh the page.

## Roles

| Role | Access |
| --- | --- |
| Administrator | Transactions, history, verification/export, policy settings and revocation |
| Operator | Transactions, history and verification/export |
| Viewer | Aggregate event count and signer status |

## Transaction example

Amounts use integer minor units: `12500` with currency `PKR` represents PKR 125.00.
The default limit is `100000` minor units. Both allowed and denied submissions receive
signed evidence. Use synthetic references such as `Demo invoice`.

Export a valid journal, edit a transaction amount in a copy, and upload that copy through
**Verify an evidence file**. The result identifies `CONTENT_ALTERED` and its event sequence;
uploaded records do not replace stored transactions.

## Independent verification and evaluation

```bash
npm run verify -- evidence.json trusted-public-keys.json
npm run verify -- evidence.json trusted-public-keys.json retained-checkpoint.json
npm run benchmark
npm run test:browser
```

Obtain `public-keys.json` through a trusted channel before a dispute. A retained checkpoint
anchors previously stored evidence and helps detect rollback. Browser tests use disposable
accounts and a temporary database. If browser discovery fails, set `BROWSER_EXECUTABLE`
to an installed Chrome, Chromium or Brave executable. Screenshots and a report are written
to `test-results/browser/`.

See [docs/guide.txt](docs/guide.txt) for workflows/recovery,
[docs/design.txt](docs/design.txt) for the architecture and threat model, and
[docs/evaluation.txt](docs/evaluation.txt) for measured checks and limitations.

## Local data and limitations

The database and private keys are generated under `data/`. Keep this directory private;
do not commit or share it. Evidence exports exclude passwords and private keys but still
contain actors and transaction references.

This is a local teaching prototype. Timestamps simulate an authority on the same host;
they do not establish independently trusted real time. Freshness requires separately
retained evidence/checkpoints. A host owner with access to private keys can forge history.
Revocation blocks new transactions while operational security auditing continues under a
separate key; recovery starts a new journal with separately trusted keys.
