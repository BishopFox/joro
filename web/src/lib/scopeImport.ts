// Scope file (.json) parsing for the Scope tab's importer. A scope file is the same
// shape the project config and the collab bundle already use:
//
//   { "scopeEnabled": true, "scopeRules": [{ pattern, methods, path, include }] }
//
// Parsing here fails early so the operator gets a useful message without a round
// trip; the server validates the rules independently and is the authority.

import { ScopeRule } from './api'

export const MAX_SCOPE_FILE_BYTES = 1 << 20

export type ScopeImportRule = Omit<ScopeRule, 'id'>

export interface ScopeImportBundle {
  scopeEnabled?: boolean
  scopeRules: ScopeImportRule[]
}

// EXAMPLE_SCOPE_FILE backs the "Download example scope file" link. Two entries, not
// one: a pattern is matched against the bare hostname, and the leading `*.` still
// requires a label, so `*.bishopfox.com` covers subdomains but not the apex.
export const EXAMPLE_SCOPE_FILE: ScopeImportBundle = {
  scopeEnabled: true,
  scopeRules: [
    { pattern: 'bishopfox.com', methods: [], path: '', include: true },
    { pattern: '*.bishopfox.com', methods: [], path: '', include: true },
  ],
}

export const EXAMPLE_SCOPE_FILENAME = 'joro-scope-example.json'

// readScopeFile reads and shape-checks a scope file, throwing an operator-readable
// Error on anything it cannot use.
export async function readScopeFile(file: File): Promise<ScopeImportBundle> {
  if (file.size > MAX_SCOPE_FILE_BYTES) {
    throw new Error(`File is too large (max ${MAX_SCOPE_FILE_BYTES >> 10} KB)`)
  }

  const buf = new Uint8Array(await file.arrayBuffer())
  if (buf.length >= 2 && buf[0] === 0x1f && buf[1] === 0x8b) {
    throw new Error('That looks like a gzipped project file — use Settings → Project → Import instead')
  }

  let parsed: unknown
  try {
    parsed = JSON.parse(new TextDecoder().decode(buf))
  } catch {
    throw new Error('Not valid JSON')
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new Error('Expected a JSON object with a scopeRules array')
  }

  const bundle = parsed as { scopeEnabled?: unknown; scopeRules?: unknown }
  if (!Array.isArray(bundle.scopeRules)) {
    throw new Error('Missing scopeRules array')
  }
  if (bundle.scopeRules.length === 0) {
    throw new Error('scopeRules is empty')
  }
  if (bundle.scopeEnabled !== undefined && typeof bundle.scopeEnabled !== 'boolean') {
    throw new Error('scopeEnabled must be true or false')
  }

  const scopeRules = bundle.scopeRules.map((raw, i) => {
    if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
      throw new Error(`Rule ${i}: expected an object`)
    }
    const r = raw as Record<string, unknown>
    if (typeof r.pattern !== 'string' || r.pattern.trim() === '') {
      throw new Error(`Rule ${i}: pattern must be a non-empty string`)
    }
    // Required rather than defaulted: false means "exclude", so an omitted flag
    // would silently invert the rule.
    if (typeof r.include !== 'boolean') {
      throw new Error(`Rule ${i}: include must be true or false`)
    }
    if (r.path !== undefined && typeof r.path !== 'string') {
      throw new Error(`Rule ${i}: path must be a string`)
    }
    if (r.methods !== undefined && !Array.isArray(r.methods)) {
      throw new Error(`Rule ${i}: methods must be an array`)
    }
    const methods = (r.methods ?? []).map((m) => {
      if (typeof m !== 'string') throw new Error(`Rule ${i}: methods must be strings`)
      return m.trim().toUpperCase()
    }).filter(Boolean)

    return {
      pattern: r.pattern.trim(),
      methods,
      path: typeof r.path === 'string' ? r.path.trim() : '',
      include: r.include,
    }
  })

  return bundle.scopeEnabled === undefined
    ? { scopeRules }
    : { scopeEnabled: bundle.scopeEnabled, scopeRules }
}
