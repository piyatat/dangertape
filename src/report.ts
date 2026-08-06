import type { Analysis, Finding, Severity } from './types.js'
import { SEVERITY_ORDER } from './types.js'

const COLORS = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  green: '\x1b[32m',
  cyan: '\x1b[36m',
  magenta: '\x1b[35m',
}

function colorize(enabled: boolean, color: string, text: string): string {
  if (!enabled) return text
  return `${color}${text}${COLORS.reset}`
}

function severityColor(sev: Severity): string {
  switch (sev) {
    case 'critical':
      return COLORS.magenta
    case 'high':
      return COLORS.red
    case 'medium':
      return COLORS.yellow
  }
}

function severityTally(findings: Finding[]): string | null {
  if (!findings.length) return null
  const counts: Partial<Record<Severity, number>> = {}
  for (const f of findings) {
    counts[f.severity] = (counts[f.severity] ?? 0) + 1
  }
  const parts = SEVERITY_ORDER.filter((sev) => (counts[sev] ?? 0) > 0).map(
    (sev) => `${counts[sev]} ${sev}`,
  )
  return parts.length ? parts.join(' · ') : null
}

/** Timeline: findings ordered by event line (chronological), with severity tags. */
export function formatText(analysis: Analysis, color: boolean): string {
  const lines: string[] = []
  const c = (col: string, t: string) => colorize(color, col, t)

  lines.push('')
  lines.push(c(COLORS.bold, 'dangertape') + c(COLORS.dim, ' · agent session replay'))
  lines.push(c(COLORS.dim, analysis.file) + ` · ${analysis.eventCount} event(s)`)
  lines.push('')
  lines.push(c(COLORS.dim, analysis.summary))
  lines.push('')

  if (!analysis.findings.length) {
    lines.push(c(COLORS.green, '✓ No destructive patterns'))
    lines.push(c(COLORS.dim, '  Tip: pass --fail in CI to exit 1 on critical/high hits.'))
    lines.push('')
    return lines.join('\n')
  }

  const tally = severityTally(analysis.findings)
  if (tally) lines.push(c(COLORS.dim, tally))
  lines.push(c(COLORS.bold, 'Timeline'))
  lines.push('')

  // Chronological for the timeline view
  const timeline = analysis.findings.slice().sort((a, b) => a.eventLine - b.eventLine)

  for (const f of timeline) {
    const tag = c(severityColor(f.severity), f.severity.toUpperCase().padEnd(8))
    const when = f.ts ? c(COLORS.dim, ` ${f.ts}`) : ''
    const tool = f.tool ? c(COLORS.cyan, ` ${f.tool}`) : ''
    lines.push(`${tag} L${String(f.eventLine).padStart(3)}${when}${tool}`)
    lines.push(`         ${c(COLORS.bold, f.title)}`)
    lines.push(c(COLORS.dim, `         ${f.detail}`))
    lines.push(c(COLORS.dim, `         evidence: ${f.evidence}`))
    lines.push('')
  }

  lines.push(
    c(
      COLORS.dim,
      'Tip: --json for pipelines · --fail exits 1 when critical/high findings exist.',
    ),
  )
  lines.push('')
  return lines.join('\n')
}

export function formatJson(analysis: Analysis): string {
  return JSON.stringify(
    {
      file: analysis.file,
      eventCount: analysis.eventCount,
      summary: analysis.summary,
      maxSeverity: analysis.maxSeverity,
      findingCount: analysis.findings.length,
      findings: analysis.findings.map((f) => ({
        id: f.id,
        severity: f.severity,
        title: f.title,
        detail: f.detail,
        evidence: f.evidence,
        patternId: f.patternId,
        eventLine: f.eventLine,
        tool: f.tool,
        ts: f.ts,
      })),
    },
    null,
    2,
  )
}
