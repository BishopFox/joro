// Payload-source model for the Fuzzer, mirroring internal/fuzzer/sources.go.
//
// A source is a compact spec (a built-in list id, or generator parameters) that
// the server resolves into payloads, so a huge numeric range never travels inline.
// `sourceCount` is a client-side mirror of the Go Count() for instant estimates;
// the server is authoritative and rejects anything over the cap, so drift only
// mis-estimates and self-heals on start. Keep the two in sync.

export type SourceKind = 'builtin' | 'numbers' | 'chars' | 'lengths' | 'dates'

// How a position gets its payloads in the UI. 'manual' is the textarea/upload path
// and never becomes a PayloadSource — it travels inline as string[].
export type SourceMode = 'manual' | 'builtin' | 'generator'

export interface PayloadSource {
  kind: SourceKind
  // builtin
  list?: string
  // numbers
  numberMode?: 'range' | 'digits'
  min?: number
  max?: number
  step?: number
  minDigits?: number
  maxDigits?: number
  pad?: number
  hex?: boolean
  upper?: boolean
  prefix?: string
  suffix?: string
  // chars / lengths
  charset?: string
  minLen?: number
  maxLen?: number
  char?: string
  // dates
  dateStart?: string
  dateEnd?: string
  dateFmt?: string
  dateStep?: number
}

export interface BuiltinInfo {
  id: string
  label: string
  description: string
  category: string
  count: number
}

export interface GeneratorInfo {
  id: string
  label: string
  description: string
}

export interface WordlistCatalog {
  builtins: BuiltinInfo[]
  generators: GeneratorInfo[]
}

export const MAX_GENERATED_PAYLOADS = 10_000_000

// Default parameters when a generator is first selected.
export function defaultSource(kind: SourceKind): PayloadSource {
  switch (kind) {
    case 'numbers':
      return { kind, numberMode: 'range', min: 0, max: 100, step: 1, pad: 0 }
    case 'chars':
      return { kind, charset: 'abcdefghijklmnopqrstuvwxyz', minLen: 1, maxLen: 2 }
    case 'lengths':
      return { kind, char: 'A', minLen: 1, maxLen: 100, step: 1 }
    case 'dates':
      return { kind, dateStart: '2020-01-01', dateEnd: '2020-12-31', dateFmt: '2006-01-02', dateStep: 1 }
    case 'builtin':
      return { kind, list: '' }
  }
}

// sourceCount mirrors Go PayloadSource.Count(): the resolved length, or -1 when the
// spec is invalid/incomplete (so the UI can disable Start without throwing).
export function sourceCount(src: PayloadSource | undefined, catalog: WordlistCatalog | null): number {
  if (!src) return -1
  switch (src.kind) {
    case 'builtin': {
      const found = catalog?.builtins.find(b => b.id === src.list)
      return found ? found.count : -1
    }
    case 'numbers': {
      if (src.numberMode === 'digits') {
        const lo = src.minDigits ?? 0
        const hi = src.maxDigits ?? 0
        if (lo < 1 || hi < lo || hi > 18) return -1
        let total = 0
        for (let w = lo; w <= hi; w++) {
          total += Math.pow(10, w)
          if (total > MAX_GENERATED_PAYLOADS) return total
        }
        return total
      }
      const step = src.step && src.step !== 0 ? src.step : 1
      const min = src.min ?? 0
      const max = src.max ?? 0
      if (step < 0 || max < min) return -1
      return Math.floor((max - min) / step) + 1
    }
    case 'chars': {
      const n = (src.charset ?? '').length
      const lo = src.minLen ?? 0
      const hi = src.maxLen ?? 0
      if (n === 0 || lo < 1 || hi < lo) return -1
      let total = 0
      for (let l = lo; l <= hi; l++) {
        total += Math.pow(n, l)
        if (total > MAX_GENERATED_PAYLOADS) return total
      }
      return total
    }
    case 'lengths': {
      const step = src.step && src.step !== 0 ? src.step : 1
      const lo = src.minLen ?? 0
      const hi = src.maxLen ?? 0
      if (step < 0 || lo < 1 || hi < lo) return -1
      return Math.floor((hi - lo) / step) + 1
    }
    case 'dates': {
      const start = Date.parse(src.dateStart ?? '')
      const end = Date.parse(src.dateEnd ?? '')
      const step = src.dateStep && src.dateStep !== 0 ? src.dateStep : 1
      if (isNaN(start) || isNaN(end) || end < start || step < 0) return -1
      const days = Math.floor((end - start) / 86_400_000) + 1
      return Math.floor((days - 1) / step) + 1
    }
  }
}
