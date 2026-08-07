#!/usr/bin/env node
import { existsSync, readFileSync, statSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { analyze } from './analyze.js'
import { ingestFile } from './ingest.js'
import { formatJson, formatText } from './report.js'
import { hasFailSeverity } from './types.js'

type Args = {
  file?: string
  json: boolean
  fail: boolean
  color: boolean
  help: boolean
  version: boolean
}

function packageVersion(): string {
  const pkgPath = join(dirname(fileURLToPath(import.meta.url)), '..', 'package.json')
  try {
    const pkg = JSON.parse(readFileSync(pkgPath, 'utf8')) as { version?: string }
    if (typeof pkg.version === 'string' && pkg.version.trim()) return pkg.version.trim()
  } catch {
    // fall through
  }
  return '0.0.0'
}

function defaultColor(): boolean {
  return Boolean(process.stdout.isTTY) && !process.env.NO_COLOR
}

function parseArgs(argv: string[]): Args {
  const args: Args = {
    json: false,
    fail: false,
    color: defaultColor(),
    help: false,
    version: false,
  }

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!
    if (a === '--help' || a === '-h') args.help = true
    else if (a === '--version' || a === '-V') args.version = true
    else if (a === '--json') args.json = true
    else if (a === '--fail') args.fail = true
    else if (a === '--color') args.color = true
    else if (a === '--no-color') args.color = false
    else if (a.startsWith('-')) {
      throw new Error(`Unknown flag: ${a}\nTry: dangertape --help`)
    } else if (args.file) {
      throw new Error(`Unexpected argument: ${a}\nTry: dangertape --help`)
    } else {
      args.file = a
    }
  }
  return args
}

function helpText(): string {
  return `
dangertape ${packageVersion()} — replay agent session tool calls; flag destructive patterns

Usage:
  dangertape [file.jsonl] [options]

Arguments:
  file.jsonl              Agent transcript (JSONL). Supports normalized events
                          plus Claude-ish and Cursor-ish tool_use / tool_call shapes.

Options:
      --json              Machine-readable report (CI / scripts)
      --fail              Exit 1 if any critical or high finding
      --color             Force ANSI colors (overrides NO_COLOR)
      --no-color          Disable ANSI colors
  -V, --version           Print version and exit
  -h, --help              Show this help

Env (optional):
  NO_COLOR                Disable ANSI colors when set

Exit codes:
  0  ok (or findings below the --fail gate)
  1  --fail gate tripped (critical/high present)
  2  usage / I/O error

Pattern pack:
  shell   rm -rf, mkfs, dd if=, curl|bash / wget|sh, chmod 777
  git     push --force / -f, reset --hard to main|master
  sql     DROP TABLE/DATABASE/…, TRUNCATE
  secret  sk- keys, Bearer tokens, API key assignments, AKIA…

Examples:
  dangertape fixtures/sample-session.jsonl
  dangertape session.jsonl --fail
  dangertape session.jsonl --json > report.json
`.trim()
}

function assertFile(path: string): string {
  const resolved = resolve(path)
  if (!existsSync(resolved)) {
    throw new Error(`File not found: ${resolved}`)
  }
  try {
    if (!statSync(resolved).isFile()) {
      throw new Error(`Not a file: ${resolved}`)
    }
  } catch (err) {
    if (
      err instanceof Error &&
      (err.message.startsWith('Not a file') || err.message.startsWith('File not found'))
    ) {
      throw err
    }
    throw new Error(`Cannot access file: ${resolved}`)
  }
  return resolved
}

function main(): void {
  let args: Args
  try {
    args = parseArgs(process.argv.slice(2))
  } catch (err) {
    console.error(err instanceof Error ? err.message : err)
    process.exitCode = 2
    return
  }

  if (args.help) {
    console.log(helpText())
    return
  }

  if (args.version) {
    console.log(`dangertape ${packageVersion()}`)
    return
  }

  if (!args.file) {
    console.error('Missing transcript file.\nTry: dangertape --help')
    process.exitCode = 2
    return
  }

  let file: string
  try {
    file = assertFile(args.file)
  } catch (err) {
    console.error(err instanceof Error ? err.message : err)
    process.exitCode = 2
    return
  }

  let events
  try {
    events = ingestFile(file)
  } catch (err) {
    console.error(err instanceof Error ? err.message : err)
    process.exitCode = 2
    return
  }

  const result = analyze(file, events)

  if (args.json) console.log(formatJson(result))
  else console.log(formatText(result, args.color))

  if (args.fail && hasFailSeverity(result.findings)) {
    console.error(
      `dangertape: failed --fail (max severity: ${result.maxSeverity ?? 'none'})`,
    )
    process.exitCode = 1
  }
}

try {
  main()
} catch (err) {
  console.error(err instanceof Error ? err.message : err)
  process.exitCode = 1
}
