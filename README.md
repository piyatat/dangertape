# DangerTape

Replay **agent session** tool calls and flag destructive patterns before they become incidents. Point it at a JSONL transcript (normalized, Claude-ish, or Cursor-ish) and get a severity-tagged timeline.

![license](https://img.shields.io/badge/license-MIT-2f6f6a?style=flat-square)
![node](https://img.shields.io/badge/node-%3E%3D18-b86a3c?style=flat-square)
![cli](https://img.shields.io/badge/cli-session%20replay-4a6fa5?style=flat-square)

## Why

Agent sessions run `Shell`, `Bash`, and SQL helpers with little human review. DangerTape is a local, zero-dependency pass over the transcript so you catch:

- Destructive shell (`rm -rf`, `mkfs`, `dd if=`, `curl|bash` / `wget|sh`, `chmod 777`)
- Dangerous git (`push --force`, `reset --hard` to `main`/`master`)
- Destructive SQL (`DROP`, `TRUNCATE`)
- Secret-shaped strings in tool outputs (`sk-…`, `Bearer …`, API key assignments, `AKIA…`)

## Quick start

```bash
npm install
npm run build
node bin/dangertape.js fixtures/sample-session.jsonl
```

Link globally from this checkout:

```bash
npm link
dangertape path/to/session.jsonl
dangertape session.jsonl --fail
dangertape session.jsonl --json > report.json
```

## Usage

```
dangertape [file.jsonl] [options]

Options:
  --json       Machine-readable report
  --fail       Exit 1 if any critical or high finding
  --color      Force ANSI colors
  --no-color   Disable ANSI colors
  -V, --version
  -h, --help
```

Exit codes: `0` ok · `1` `--fail` gate · `2` usage / I/O error.

## Transcript formats

DangerTape accepts **JSONL** (one JSON object per line). Three shapes are recognized:

### Normalized

```json
{"ts":"2026-08-06T10:00:00Z","type":"tool_call","tool":"Shell","input":"rm -rf /tmp/x"}
{"ts":"2026-08-06T10:00:01Z","type":"tool_result","tool":"Shell","output":"…"}
```

### Claude-ish

```json
{"type":"tool_use","name":"Bash","input":{"command":"git push --force origin main"}}
{"type":"tool_result","content":"ok"}
{"role":"assistant","content":[{"type":"text","text":"Bearer …"}]}
```

### Cursor-ish

```json
{"type":"tool_call","toolName":"Shell","args":{"command":"npm test"}}
{"role":"tool","name":"Shell","content":"PASS"}
```

Unknown objects are still ingested as generic events (payload stringified) so mixed exports do not fail the run.

## Sample fixture

`fixtures/sample-session.jsonl` mixes safe reads/tests with intentional hits: `rm -rf`, force-push, hard reset to main, `DROP`/`TRUNCATE`, `mkfs`/`dd`, `curl|bash`, `chmod 777`, and secret-shaped outputs.

```bash
node bin/dangertape.js fixtures/sample-session.jsonl --no-color
node bin/dangertape.js fixtures/sample-session.jsonl --fail   # exits 1
```

## Pattern pack

| Category | Patterns | Typical severity |
| --- | --- | --- |
| shell | `rm -rf` / `-fr`, `mkfs`, `dd if=`, `curl`/`wget` piped to `sh`/`bash`, `chmod …777` / `a+rwx` | critical / high |
| git | `git push --force` / `-f` / `--force-with-lease`, `git reset --hard` … `main`\|`master` | critical / high |
| sql | `DROP TABLE/DATABASE/…`, `TRUNCATE` | critical / high |
| secret | `sk-…`, `Bearer …`, `api_key=` assignments, `AKIA…` | high / medium |

Secret matches are **redacted** in the report (prefix/suffix only).

## Report

Human output is a **timeline** ordered by JSONL line number, with `critical` / `high` / `medium` tags. `--json` emits a structured object (`file`, `eventCount`, `maxSeverity`, `findings[]`) for CI.

## Stack

- TypeScript → `tsc` (ES2022, NodeNext)
- No runtime dependencies
- Node `>=18`

## License

MIT
