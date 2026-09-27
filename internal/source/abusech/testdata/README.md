# Test data

| File | Source |
|---|---|
| `get_info_full.json` | Hand-written `get_info` response with every field populated, following the shape of MalwareBazaar's API documentation. Not a captured response: it contains no real sample, reporter or credential. |
| `get_info_sparse.json` | Hand-written `get_info` response exercising nulls, empty lists, `{}` for `vendor_intel`, `"n/a"` for `trid` and the export timestamp layout with a zone. |
| `get_info_full.golden.json` | The published sample file for `get_info_full.json`, generated on 2026-09-27 by the code at commit `e7b8ce62`, before the style-guide refactor. |
| `get_info_sparse.golden.json` | The published sample file for `get_info_sparse.json`, generated the same way. |

The golden files pin the published JSON format byte for byte, because thousands of files on the
`data` branch already use it. If a change to the format is intended, regenerate them with:

```bash
go test ./internal/source/abusech -run TestClientAggregate -update
```

and review the diff like any other change.

Replacing the hand-written fixtures with captured, sanitised responses (API keys, email
addresses and personal data removed) would make the tests closer to reality.
