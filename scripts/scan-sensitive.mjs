#!/usr/bin/env node

/* global process */

/**
 * Privacy guard for a repository that may become public.
 *
 * Findings print only file, line, and rule names. The matched value is never
 * echoed because CI logs can become public too.
 */

import { execFileSync } from 'node:child_process'
import { readFileSync, statSync } from 'node:fs'
import path from 'node:path'

const SKIP_DIRS = new Set(['node_modules', 'vendor', '.git', 'build', 'coverage'])
const SKIP_FILES = new Set(['composer.lock', 'pnpm-lock.yaml', 'scripts/scan-sensitive.mjs'])
const SKIP_EXTENSIONS = new Set([
  '.gif', '.ico', '.jpeg', '.jpg', '.png', '.svg', '.webp',
  '.eot', '.ttf', '.woff', '.woff2',
])
const FORBIDDEN_EXTENSIONS = new Set([
  '.bak', '.csv', '.db', '.doc', '.docx', '.dump', '.eml', '.mbox',
  '.ndjson', '.ofx', '.pdf', '.qbo', '.qfx', '.sql', '.sqlite', '.sqlite3',
  '.tsv', '.xls', '.xlsx', '.zip',
])
const FORBIDDEN_PATHS = [
  /^(?:backups?|billing-data|client-data|data|dumps?|exports?|production-data)\//i,
  /^database\/(?:backups?|dumps?)\//i,
  /^storage\/app\/(?:private|uploads?)\/(?!\.gitignore$)/i,
]

const RULES = [
  {
    name: 'us-ssn',
    pattern: /\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g,
  },
  {
    name: 'payment-card-number',
    pattern: /\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13}|6(?:011|5\d{2})\d{12})\b/g,
  },
  {
    name: 'bank-account-label',
    pattern: /\b(?:bank|routing|account)[ _-]?(?:number|no|id)\b[^A-Za-z0-9]{0,4}[A-Z0-9]{6,17}\b/gi,
  },
  {
    name: 'tax-identifier',
    pattern: /\b(?:ein|tax(?:payer)?[ _-]?id(?:entification)?(?:[ _-]?(?:number|no))?)\b[^A-Za-z0-9]{0,6}\d{2}-\d{7}\b/gi,
  },
  {
    name: 'stripe-live-credential',
    pattern: /\b(?:sk|rk)_live_[A-Za-z0-9]{16,}\b/g,
  },
  {
    name: 'stripe-webhook-secret',
    pattern: /\bwhsec_[A-Za-z0-9]{16,}\b/g,
  },
  {
    name: 'payment-processor-record-id',
    pattern: /\b(?:acct|ch|cus|in|pi|pm|seti|src|sub|txn)_[A-Za-z0-9]{14,}\b/g,
  },
  {
    name: 'non-test-email',
    pattern: /\b[A-Za-z0-9._%+-]+@(?!example\.(?:com|org|net)\b)(?![^\s@]*\.(?:test|invalid|localhost)\b)[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
    ignore: /^git@github\.com$|@(?:bherila\.net|users\.noreply\.github\.com|sentry\.io)\b|\{|\}|\$|:[a-z]/i,
  },
]

const stagedOnly = process.argv.includes('--staged')
const gitArguments = stagedOnly
  ? ['diff', '--cached', '--name-only', '--diff-filter=ACMR']
  : ['ls-files', '--cached', '--others', '--exclude-standard']
const files = execFileSync('git', gitArguments, { encoding: 'utf8' })
  .split('\n')
  .map((file) => file.trim())
  .filter(Boolean)
const findings = []

for (const file of files) {
  const extension = path.extname(file).toLowerCase()

  if (
    FORBIDDEN_EXTENSIONS.has(extension)
    || FORBIDDEN_PATHS.some((pattern) => pattern.test(file))
  ) {
    findings.push({ file, line: 0, rule: 'private-data-file' })
    continue
  }

  if (
    SKIP_FILES.has(file)
    || SKIP_EXTENSIONS.has(extension)
    || file.split('/').some((segment) => SKIP_DIRS.has(segment))
  ) {
    continue
  }

  try {
    if (statSync(file).size > 2 * 1024 * 1024) {
continue
}
  } catch {
    continue
  }

  let contents

  try {
    contents = readFileSync(file, 'utf8')
  } catch {
    continue
  }

  if (contents.includes('\u0000')) {
continue
}

  for (const [index, line] of contents.split('\n').entries()) {
    if (line.includes('sensitive-scan-ignore')) {
continue
}

    for (const rule of RULES) {
      rule.pattern.lastIndex = 0
      let match

      while ((match = rule.pattern.exec(line)) !== null) {
        if (rule.ignore?.test(match[0])) {
continue
}

        findings.push({ file, line: index + 1, rule: rule.name })
      }
    }
  }
}

if (findings.length === 0) {
  console.log(`sensitive-scan: clean (${stagedOnly ? 'staged changes' : 'working tree'})`)
  process.exit(0)
}

console.error(`sensitive-scan: ${findings.length} potential disclosure(s); values are redacted`)

for (const finding of findings) {
  console.error(`${finding.file}:${finding.line} [${finding.rule}]`)
}

process.exit(1)
