import { readFileSync } from 'node:fs'
import type { EventKind, SessionEvent } from './types.js'

type JsonRecord = Record<string, unknown>

function isRecord(v: unknown): v is JsonRecord {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

function asString(v: unknown): string | undefined {
  if (typeof v === 'string') return v
  if (typeof v === 'number' || typeof v === 'boolean') return String(v)
  return undefined
}

function stringifyPayload(v: unknown): string | undefined {
  if (v == null) return undefined
  if (typeof v === 'string') return v
  if (typeof v === 'number' || typeof v === 'boolean') return String(v)
  try {
    return JSON.stringify(v)
  } catch {
    return String(v)
  }
}

function pickTs(obj: JsonRecord): string | undefined {
  return (
    asString(obj.ts) ??
    asString(obj.timestamp) ??
    asString(obj.created_at) ??
    asString(obj.time)
  )
}

/** Flatten nested tool input objects into a scannable string. */
function flattenInput(input: unknown): string | undefined {
  if (input == null) return undefined
  if (typeof input === 'string') return input
  if (!isRecord(input)) return stringifyPayload(input)

  const preferred = [
    'command',
    'cmd',
    'shell',
    'code',
    'query',
    'sql',
    'content',
    'text',
    'prompt',
    'arguments',
  ]
  for (const key of preferred) {
    if (key in input) {
      const v = input[key]
      if (typeof v === 'string' && v.trim()) return v
      if (isRecord(v) || Array.isArray(v)) {
        const nested = flattenInput(v)
        if (nested) return nested
      }
    }
  }
  return stringifyPayload(input)
}

function flattenOutput(output: unknown): string | undefined {
  if (output == null) return undefined
  if (typeof output === 'string') return output
  if (!isRecord(output)) return stringifyPayload(output)

  const preferred = ['output', 'result', 'content', 'text', 'stdout', 'stderr', 'message']
  for (const key of preferred) {
    if (key in output) {
      const v = output[key]
      if (typeof v === 'string') return v
      if (Array.isArray(v)) {
        // Claude-style content blocks
        const parts = v
          .map((block) => {
            if (!isRecord(block)) return stringifyPayload(block) ?? ''
            return asString(block.text) ?? asString(block.content) ?? stringifyPayload(block) ?? ''
          })
          .filter(Boolean)
        if (parts.length) return parts.join('\n')
      }
    }
  }
  return stringifyPayload(output)
}

function inferKind(obj: JsonRecord, tool?: string, input?: string, output?: string): EventKind {
  const type = (asString(obj.type) ?? asString(obj.event) ?? asString(obj.role) ?? '').toLowerCase()
  if (
    type.includes('tool_use') ||
    type.includes('tool_call') ||
    type.includes('toolcall') ||
    type === 'tool'
  ) {
    return 'tool_call'
  }
  if (type.includes('tool_result') || type.includes('tool_response') || type === 'function_result') {
    return 'tool_result'
  }
  if (type === 'assistant' || type === 'user' || type === 'message' || type === 'system') {
    return 'message'
  }
  if (tool || input) return 'tool_call'
  if (output && !input) return 'tool_result'
  return 'unknown'
}

/**
 * Normalized DangerTape event:
 *   { "ts", "type": "tool_call"|"tool_result"|"message", "tool", "input", "output" }
 */
function tryNormalized(obj: JsonRecord, line: number): SessionEvent | null {
  const type = (asString(obj.type) ?? '').toLowerCase()
  if (!['tool_call', 'tool_result', 'message', 'unknown'].includes(type) && !('tool' in obj)) {
    return null
  }
  // Require at least one of tool/input/output or explicit type
  if (!('tool' in obj) && !('input' in obj) && !('output' in obj) && !type) return null
  if (type && !['tool_call', 'tool_result', 'message', 'unknown'].includes(type) && !('tool' in obj)) {
    return null
  }

  const tool = asString(obj.tool) ?? asString(obj.name)
  const input = flattenInput(obj.input ?? obj.command ?? obj.args)
  const output = flattenOutput(obj.output ?? obj.result)
  if (!tool && !input && !output && !type) return null

  // Prefer explicit normalized types
  if (['tool_call', 'tool_result', 'message', 'unknown'].includes(type)) {
    return {
      line,
      ts: pickTs(obj),
      kind: type as EventKind,
      tool: tool ?? undefined,
      input: input ?? undefined,
      output: output ?? undefined,
      sourceFormat: 'normalized',
    }
  }

  // Has tool/input/output fields without Claude/Cursor markers → treat as normalized-ish
  if ('tool' in obj || 'input' in obj || 'output' in obj) {
    return {
      line,
      ts: pickTs(obj),
      kind: inferKind(obj, tool, input, output),
      tool: tool ?? undefined,
      input: input ?? undefined,
      output: output ?? undefined,
      sourceFormat: 'normalized',
    }
  }
  return null
}

/**
 * Claude Messages API / Anthropic transcript shape:
 *   { "type": "tool_use", "name": "Bash", "input": { "command": "…" } }
 *   { "type": "tool_result", "content": "…" }
 *   { "role": "assistant", "content": [ { "type": "tool_use", … } ] }
 */
function tryClaude(obj: JsonRecord, line: number): SessionEvent | null {
  const type = (asString(obj.type) ?? '').toLowerCase()
  const role = (asString(obj.role) ?? '').toLowerCase()

  if (type === 'tool_use' || type === 'server_tool_use') {
    const tool = asString(obj.name) ?? asString(obj.tool)
    const input = flattenInput(obj.input)
    return {
      line,
      ts: pickTs(obj),
      kind: 'tool_call',
      tool: tool ?? undefined,
      input: input ?? undefined,
      sourceFormat: 'claude',
    }
  }

  if (type === 'tool_result') {
    return {
      line,
      ts: pickTs(obj),
      kind: 'tool_result',
      tool: asString(obj.name) ?? asString(obj.tool_use_id) ?? undefined,
      output: flattenOutput(obj.content ?? obj.output),
      sourceFormat: 'claude',
    }
  }

  // Assistant / user message with content blocks
  if ((role === 'assistant' || role === 'user') && Array.isArray(obj.content)) {
    const blocks = obj.content.filter(isRecord)
    const toolUse = blocks.find((b) => asString(b.type)?.toLowerCase() === 'tool_use')
    if (toolUse) {
      return {
        line,
        ts: pickTs(obj),
        kind: 'tool_call',
        tool: asString(toolUse.name) ?? undefined,
        input: flattenInput(toolUse.input),
        sourceFormat: 'claude',
      }
    }
    const toolResult = blocks.find((b) => asString(b.type)?.toLowerCase() === 'tool_result')
    if (toolResult) {
      return {
        line,
        ts: pickTs(obj),
        kind: 'tool_result',
        output: flattenOutput(toolResult.content ?? toolResult.output),
        sourceFormat: 'claude',
      }
    }
    const texts = blocks
      .map((b) => asString(b.text) ?? '')
      .filter(Boolean)
      .join('\n')
    if (texts) {
      return {
        line,
        ts: pickTs(obj),
        kind: 'message',
        output: texts,
        sourceFormat: 'claude',
      }
    }
  }

  return null
}

/**
 * Cursor-ish agent transcript:
 *   { "type": "tool_call", "toolName": "Shell", "args": { "command": "…" } }
 *   { "role": "tool", "name": "Shell", "content": "…" }
 *   { "toolCall": { "name": "run_terminal_cmd", "arguments": { "command": "…" } } }
 */
function tryCursor(obj: JsonRecord, line: number): SessionEvent | null {
  const type = (asString(obj.type) ?? '').toLowerCase()
  const role = (asString(obj.role) ?? '').toLowerCase()

  if (
    type === 'tool_call' ||
    type === 'function_call' ||
    ('toolName' in obj && ('args' in obj || 'arguments' in obj || 'input' in obj))
  ) {
    const tool =
      asString(obj.toolName) ?? asString(obj.tool_name) ?? asString(obj.name) ?? asString(obj.tool)
    const input = flattenInput(obj.args ?? obj.arguments ?? obj.input ?? obj.params)
    return {
      line,
      ts: pickTs(obj),
      kind: 'tool_call',
      tool: tool ?? undefined,
      input: input ?? undefined,
      sourceFormat: 'cursor',
    }
  }

  if (isRecord(obj.toolCall) || isRecord(obj.tool_call)) {
    const tc = (obj.toolCall ?? obj.tool_call) as JsonRecord
    const tool = asString(tc.name) ?? asString(tc.toolName)
    const input = flattenInput(tc.arguments ?? tc.args ?? tc.input)
    return {
      line,
      ts: pickTs(obj),
      kind: 'tool_call',
      tool: tool ?? undefined,
      input: input ?? undefined,
      sourceFormat: 'cursor',
    }
  }

  if (role === 'tool' || type === 'tool_result' || type === 'function_result') {
    return {
      line,
      ts: pickTs(obj),
      kind: 'tool_result',
      tool: asString(obj.name) ?? asString(obj.toolName) ?? undefined,
      output: flattenOutput(obj.content ?? obj.output ?? obj.result),
      sourceFormat: 'cursor',
    }
  }

  return null
}

function parseLine(raw: string, line: number): SessionEvent | null {
  const trimmed = raw.trim()
  if (!trimmed || trimmed.startsWith('#')) return null

  let parsed: unknown
  try {
    parsed = JSON.parse(trimmed)
  } catch {
    throw new Error(`Invalid JSON on line ${line}`)
  }

  if (!isRecord(parsed)) {
    throw new Error(`JSONL line ${line} must be an object`)
  }

  // Prefer Claude / Cursor specific shapes first (richer type tags), then normalized
  return tryClaude(parsed, line) ?? tryCursor(parsed, line) ?? tryNormalized(parsed, line) ?? {
    line,
    ts: pickTs(parsed),
    kind: 'unknown',
    input: stringifyPayload(parsed),
    sourceFormat: 'generic',
  }
}

export function ingestFile(path: string): SessionEvent[] {
  const text = readFileSync(path, 'utf8')
  return ingestJsonl(text)
}

export function ingestJsonl(text: string): SessionEvent[] {
  const lines = text.split(/\r?\n/)
  const events: SessionEvent[] = []
  for (let i = 0; i < lines.length; i++) {
    const lineNo = i + 1
    const raw = lines[i]!
    if (!raw.trim()) continue
    const ev = parseLine(raw, lineNo)
    if (ev) events.push(ev)
  }
  return events
}
