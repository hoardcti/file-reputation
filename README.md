# file-reputation

Collects file hash reputation data from public threat intelligence sources and emits it as normalised Hoard CTI records.

![Dynamic JSON Badge](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fraw.githubusercontent.com%2Fhoardcti%2Ffile-reputation%2Frefs%2Fheads%2Fmain%2Fstats.json&query=files&label=Hashed%20Files&color=A1BC98&style=flat-square) ![Dynamic JSON Badge](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fraw.githubusercontent.com%2Fhoardcti%2Ffile-reputation%2Frefs%2Fheads%2Fmain%2Fstats.json&query=last_edit_display&label=Last%20Updated&color=A1BC98&style=flat-square)


## Overview

Security tooling often needs to answer one question quickly: *is this file hash known, and what is known about it?* Public sources publish this data in different formats, hash algorithms and timestamp conventions, so every consumer ends up writing the same parsers.

[`file-reputation`](https://github.com/hoardcti/file-reputation) is a Hoard CTI source module. It pulls hash lists and sample metadata from upstream sources and stores each sample as its own JSON file, named by its SHA256 hash.

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

### API

The API is the recommended way to query single hashes. It returns proper JSON on both hits and misses, and it is stable across the storage changes described below.

Look up a hash:

```bash
curl -fsSL https://api.hoardcti.com/v1/file-reputation/<sha256>
```

A `404` with `{"query_status":"not_found"}` means the hash is not in the dataset.

Module metadata — version, record count, last update time and repository URL:

```bash
curl -fsSL https://api.hoardcti.com/v1/file-reputation
```

Lookups are by SHA256 only. Responses are cached for 5 minutes.

### Direct access

> [!WARNING]
> Storing output on the `data` branch is **temporary**. The storage and distribution mechanism will change as Hoard CTI's architecture is finalised. Do not build production integrations against the `data` branch or its layout — use the API above.

All collected data is currently committed to the [`data`](https://github.com/hoardcti/file-reputation/tree/data) branch as one JSON file per sample, named `<sha256>.json`.

```bash
curl -fsSL https://raw.githubusercontent.com/hoardcti/file-reputation/data/<sha256>.json
```

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
# Run
go run -tags dev ./cmd/aggregate

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
