import { patternPack } from './patterns.js'
import type { Analysis, Finding, SessionEvent } from './types.js'
import { maxSeverity } from './types.js'

function scanText(
  text: string | undefined,
  target: 'input' | 'output',
  event: SessionEvent,
  findings: Finding[],
): void {
  if (!text || !text.trim()) return
  for (const pat of patternPack()) {
    if (pat.target !== target && pat.target !== 'both') continue
    const result = pat.test(text)
    if (!result.hit) continue
    findings.push({
      id: `${pat.id}@${event.line}`,
      severity: pat.severity,
      title: pat.title,
      detail: `${pat.category} pattern \`${pat.id}\` matched in ${target}`,
      evidence: result.evidence,
      patternId: pat.id,
      eventLine: event.line,
      tool: event.tool,
      ts: event.ts,
    })
  }
}

export function analyze(file: string, events: SessionEvent[]): Analysis {
  const findings: Finding[] = []

  for (const event of events) {
    scanText(event.input, 'input', event, findings)
    scanText(event.output, 'output', event, findings)
    // Messages: treat body as output (secret leak surface)
    if (event.kind === 'message' && event.input && !event.output) {
      scanText(event.input, 'output', event, findings)
    }
  }

  // Stable order: severity desc, then line asc
  const rank = { critical: 3, high: 2, medium: 1 } as const
  findings.sort((a, b) => {
    const d = rank[b.severity] - rank[a.severity]
    if (d !== 0) return d
    return a.eventLine - b.eventLine
  })

  const max = maxSeverity(findings)
  const summary = summarize(events.length, findings, max)

  return {
    file,
    eventCount: events.length,
    findings,
    summary,
    maxSeverity: max,
  }
}

function summarize(
  eventCount: number,
  findings: Finding[],
  max: Analysis['maxSeverity'],
): string {
  if (!findings.length) {
    return `Scanned ${eventCount} event(s) · no destructive patterns flagged.`
  }
  const counts = { critical: 0, high: 0, medium: 0 }
  for (const f of findings) counts[f.severity]++
  const parts = (['critical', 'high', 'medium'] as const)
    .filter((s) => counts[s] > 0)
    .map((s) => `${counts[s]} ${s}`)
  return `Scanned ${eventCount} event(s) · ${findings.length} finding(s) (${parts.join(', ')}) · max ${max}.`
}
