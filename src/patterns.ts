import type { Severity } from './types.js'

export type PatternTarget = 'input' | 'output' | 'both'

export type Pattern = {
  id: string
  severity: Severity
  title: string
  /** Category for report grouping. */
  category: 'shell' | 'git' | 'sql' | 'secret'
  target: PatternTarget
  test: (text: string) => { hit: boolean; evidence: string }
}

function matchRe(re: RegExp, text: string, redact = false): { hit: boolean; evidence: string } {
  re.lastIndex = 0
  const m = re.exec(text)
  if (!m) return { hit: false, evidence: '' }
  const raw = m[0]
  const evidence = redact ? redactSecret(raw) : truncate(raw, 120)
  return { hit: true, evidence }
}

function truncate(s: string, n: number): string {
  const one = s.replace(/\s+/g, ' ').trim()
  return one.length <= n ? one : `${one.slice(0, n - 1)}…`
}

function redactSecret(s: string): string {
  if (s.length <= 8) return '***'
  return `${s.slice(0, 4)}…${s.slice(-2)} (${s.length} chars)`
}

/** Destructive shell commands. */
const SHELL_PATTERNS: Pattern[] = [
  {
    id: 'shell-rm-rf',
    severity: 'critical',
    title: 'Recursive force delete',
    category: 'shell',
    target: 'input',
    test: (t) => matchRe(/\brm\s+(-[^\s]*f[^\s]*\s+-[^\s]*r[^\s]*|-[^\s]*r[^\s]*\s+-[^\s]*f[^\s]*|-[^\s]*rf[^\s]*|-[^\s]*fr[^\s]*)\b/i, t),
  },
  {
    id: 'shell-mkfs',
    severity: 'critical',
    title: 'Filesystem format (mkfs)',
    category: 'shell',
    target: 'input',
    test: (t) => matchRe(/\bmkfs(\.\w+)?\b/i, t),
  },
  {
    id: 'shell-dd',
    severity: 'critical',
    title: 'Raw disk write (dd if=)',
    category: 'shell',
    target: 'input',
    test: (t) => matchRe(/\bdd\s+.*\bif=/i, t),
  },
  {
    id: 'shell-pipe-to-shell',
    severity: 'critical',
    title: 'Remote content piped to shell',
    category: 'shell',
    target: 'input',
    test: (t) =>
      matchRe(
        /\b(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(ba)?sh\b|\b(ba)?sh\s+<\(\s*(curl|wget)\b/i,
        t,
      ),
  },
  {
    id: 'shell-chmod-world',
    severity: 'high',
    title: 'World-writable chmod (777 / a+rwx)',
    category: 'shell',
    target: 'input',
    test: (t) =>
      matchRe(/\bchmod\s+(?:-[A-Za-z]+\s+)*(?:[0-7]*777|a\+rwx)\b/i, t),
  },
]

/** Dangerous git operations. */
const GIT_PATTERNS: Pattern[] = [
  {
    id: 'git-force-push',
    severity: 'critical',
    title: 'Force push',
    category: 'git',
    target: 'input',
    test: (t) =>
      matchRe(
        /\bgit\s+push\b[^\n]*(\s--force\b|\s-f\b|\s--force-with-lease\b)/i,
        t,
      ),
  },
  {
    id: 'git-reset-hard-main',
    severity: 'high',
    title: 'Hard reset targeting main/master',
    category: 'git',
    target: 'input',
    test: (t) =>
      matchRe(
        /\bgit\s+reset\s+--hard\b[^\n]*\b(origin\/)?(main|master)\b/i,
        t,
      ),
  },
]

/** Destructive SQL. */
const SQL_PATTERNS: Pattern[] = [
  {
    id: 'sql-drop',
    severity: 'critical',
    title: 'SQL DROP',
    category: 'sql',
    target: 'input',
    test: (t) => matchRe(/\bDROP\s+(TABLE|DATABASE|SCHEMA|INDEX|VIEW|USER)\b/i, t),
  },
  {
    id: 'sql-truncate',
    severity: 'high',
    title: 'SQL TRUNCATE',
    category: 'sql',
    target: 'input',
    test: (t) => matchRe(/\bTRUNCATE\s+(TABLE\s+)?\w+/i, t),
  },
]

/** Secret-shaped strings in tool outputs / messages. */
const SECRET_PATTERNS: Pattern[] = [
  {
    id: 'secret-sk-key',
    severity: 'high',
    title: 'Secret-shaped sk- key',
    category: 'secret',
    target: 'output',
    test: (t) => matchRe(/\bsk-[A-Za-z0-9_-]{16,}\b/g, t, true),
  },
  {
    id: 'secret-bearer',
    severity: 'high',
    title: 'Bearer token in output',
    category: 'secret',
    target: 'output',
    test: (t) => matchRe(/\bBearer\s+[A-Za-z0-9._\-+=\/]{20,}/gi, t, true),
  },
  {
    id: 'secret-api-key-assign',
    severity: 'medium',
    title: 'API key assignment shape',
    category: 'secret',
    target: 'both',
    test: (t) =>
      matchRe(
        /(?:api[_-]?key|apikey|secret[_-]?key)\s*[:=]\s*['"]?[A-Za-z0-9_\-]{16,}['"]?/gi,
        t,
        true,
      ),
  },
  {
    id: 'secret-aws-akia',
    severity: 'high',
    title: 'AWS access key id shape',
    category: 'secret',
    target: 'output',
    test: (t) => matchRe(/\bAKIA[0-9A-Z]{16}\b/g, t, true),
  },
]

export function patternPack(): Pattern[] {
  return [...SHELL_PATTERNS, ...GIT_PATTERNS, ...SQL_PATTERNS, ...SECRET_PATTERNS]
}
