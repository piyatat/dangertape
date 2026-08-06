export type Severity = 'critical' | 'high' | 'medium'

export type EventKind = 'tool_call' | 'tool_result' | 'message' | 'unknown'

/** Normalized tool / transcript event after ingest. */
export type SessionEvent = {
  /** 1-based line number in the source JSONL. */
  line: number
  /** ISO-ish timestamp when present. */
  ts?: string
  kind: EventKind
  /** Tool name (Shell, Bash, Write, …) when known. */
  tool?: string
  /** Primary command / input payload scanned for patterns. */
  input?: string
  /** Tool output / assistant text scanned for secrets. */
  output?: string
  /** Original format tag for debugging. */
  sourceFormat: 'normalized' | 'claude' | 'cursor' | 'generic'
}

export type Finding = {
  id: string
  severity: Severity
  title: string
  detail: string
  /** Matched snippet (may be truncated / redacted for secrets). */
  evidence: string
  patternId: string
  eventLine: number
  tool?: string
  ts?: string
}

export type Analysis = {
  file: string
  eventCount: number
  findings: Finding[]
  summary: string
  maxSeverity: Severity | null
}

export const SEVERITY_RANK: Record<Severity, number> = {
  medium: 1,
  high: 2,
  critical: 3,
}

export const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium']

export function maxSeverity(findings: Finding[]): Severity | null {
  let best: Severity | null = null
  for (const f of findings) {
    if (!best || SEVERITY_RANK[f.severity] > SEVERITY_RANK[best]) best = f.severity
  }
  return best
}

export function hasFailSeverity(findings: Finding[]): boolean {
  return findings.some((f) => f.severity === 'critical' || f.severity === 'high')
}
