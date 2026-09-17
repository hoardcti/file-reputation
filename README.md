# file-reputation

Collects file hash reputation data from public threat intelligence sources and emits it as normalised Hoard CTI records.

## Overview

Security tooling often needs to answer one question quickly: *is this file hash known, and what is known about it?* Public sources publish this data in different formats, hash algorithms and timestamp conventions, so every consumer ends up writing the same parsers.

`file-reputation` is a Hoard CTI source module. It pulls hash lists and sample metadata from upstream sources and stores each sample as its own JSON file, named by its SHA256 hash.

It stores reputation data only. It does not download, execute or scan files.

It is intended for:

- **Hoard CTI operators** running the aggregation platform
- **Defenders and tool authors** who want a normalised, pull-based hash reputation feed without writing per-source integrations

### Sources

| Source | Data |
|---|---|
| [MalwareBazaar (abuse.ch)](https://bazaar.abuse.ch/) | Malware sample hashes (SHA256, SHA1, MD5), imphash, TLSH, ssdeep, signature, tags |

### Output

Each record is written to its own JSON file, named by the file's SHA256 hash. Timestamps are normalised to RFC 3339 UTC.

## Installation

This module is designed to run on GitHub Actions workers, so there is nothing to install to consume its data. The workflows in [`.github/workflows/`](.github/workflows/) build and run it automatically.

To run it on a fork, add your abuse.ch Auth-Key as a repository secret named `ABUSECH_AUTH_KEY`.

For local development, build from source (requires Go 1.22 or later):

```bash
git clone https://github.com/hoardcti/file-reputation.git
cd file-reputation
go build ./...
```

## Usage

> [!WARNING]
> Storing output on the `data` branch is **temporary**. The storage and distribution mechanism will change as Hoard CTI's architecture is finalised. Do not build production integrations against the `data` branch or its layout.

All collected data is currently committed to the [`data`](https://github.com/hoardcti/file-reputation/tree/data) branch as one JSON file per sample, named `<sha256>.json`.

Look up a single hash:

```bash
curl -fsSL https://raw.githubusercontent.com/hoardcti/file-reputation/data/<sha256>.json
```

A `404` means the hash is not in the dataset.

Fetch the whole dataset:

```bash
git clone --branch data --single-branch --depth 1 https://github.com/hoardcti/file-reputation.git file-reputation-data
```

## Development

```bash
# Run the baseline checks this repository inherits from the template
python -m unittest discover -s .github/scripts -p "test_*.py" -v

# Lint and format Python (configured in pyproject.toml)
ruff check . && ruff format --check .

# Audit GitHub Actions workflows for security problems
zizmor --config .github/zizmor.yml .github/workflows/

# Scan the working tree for credentials before committing
python .github/scripts/secret_scan.py --mode tree
```

```bash
# Build
go build ./...

# Test
go test ./...

# Vet and check formatting
go vet ./...
test -z "$(gofmt -l .)"
```

Never commit Auth-Keys. Supply them through environment variables only.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). All participants are bound by the
[Code of Conduct](CODE_OF_CONDUCT.md).

## Security

Never report a vulnerability in a public issue — see [SECURITY.md](SECURITY.md)
for the private disclosure process.

## Licence

Licensed under the GNU General Public License v3.0 — see [LICENSE](LICENSE).

- [MalwareBazaar (abuse.ch)](https://bazaar.abuse.ch/) data is published under CC0.
