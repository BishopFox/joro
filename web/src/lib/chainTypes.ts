// Types for the Chain tab, mirroring internal/chain and internal/chainrun.
//
// These live beside api.ts rather than in the store because api.ts references
// them in its signatures and the store imports them too; putting them in the
// store would make api.ts depend on a zustand module. Same arrangement as
// sjTypes.ts.

export type ChainSourceKind = 'header' | 'cookie' | 'json' | 'regex' | 'between'
export type ChainVariantKind = 'baseline' | 'omit' | 'repeat' | 'move'
export type ChainRunStatus = 'running' | 'complete' | 'stopped'

// Cell and verdict are computed server-side and ship on every result, so there
// is no second copy of the rubric here to drift. chainStatus.tsx renders them.
export type ChainCell = 'ok' | 'changed' | 'blocked' | 'unresolved' | 'skipped' | 'error'
export type ChainVerdictKind =
  | 'baseline'
  | 'bypassed'
  | 'enforced'
  | 'amplified'
  | 'idempotent'
  | 'inconclusive'

export type ChainOnMissing = 'fail' | 'recorded'

export interface ChainSpan {
  start: number
  end: number
}

export interface ChainSource {
  kind: ChainSourceKind
  name?: string
  path?: string
  expr?: string
  group?: number
  prefix?: string
  suffix?: string
}

export interface ChainEdit {
  op: string
  name?: string
  value?: string
  find?: string
  regex?: boolean
  all?: boolean
  count?: number
}

export interface ChainBinding {
  id: string
  var: string
  fromStep: string
  source: ChainSource
  toStep: string
  spans: ChainSpan[]
  recorded: string
  onMissing?: ChainOnMissing
  auto?: boolean
}

export interface ChainStep {
  id: string
  label: string
  scheme: string
  host: string
  /** base64 — a captured request is routinely not UTF-8. */
  reqRaw: string
  respRaw: string
  originSeq?: number
  setup?: boolean
  edits?: ChainEdit[]
  /** Derived server-side so the canvas can badge a node without decoding bytes. */
  method?: string
}

export interface Chain {
  id: string
  name: string
  goalStepId?: string
  steps: ChainStep[]
  bindings: ChainBinding[]
  createdAt: string
  updatedAt: string
  warning?: string
}

export interface ChainSummary {
  id: string
  name: string
  steps: number
  bindings: number
  hosts: string[]
  createdAt: string
  updatedAt: string
}

export interface ChainVariant {
  id: string
  kind: ChainVariantKind
  label: string
  steps: string[]
  target?: string
}

export interface ChainMissing {
  var: string
  fromStep: string
}

export interface ChainResult {
  index: number
  variantId: string
  stepId: string
  label: string
  method: string
  url: string
  occurrence: number
  cell: ChainCell
  status: number
  len: number
  durationMs: number
  bhash?: string
  shash?: string
  chash?: string
  words?: number
  lines?: number
  note?: string
  seq?: number
  requestId?: string
  seqNote?: string
  missing?: ChainMissing[]
  captured?: string[]
  error?: string
}

export interface ChainVerdict {
  variantId: string
  kind: ChainVariantKind
  label: string
  verdict: ChainVerdictKind
  detail?: string
}

export interface ChainStepHead {
  id: string
  label: string
  method: string
  setup?: boolean
  goal?: boolean
}

export interface ChainRunSummary {
  id: string
  chainId: string
  chainName: string
  status: ChainRunStatus
  total: number
  stride: number
  completed: number
  errors: number
  unresolved: number
  bypassed: number
  createdAt: string
}

export interface ChainRunDetail extends ChainRunSummary {
  steps: ChainStepHead[]
  variants: ChainVariant[]
  verdicts: ChainVerdict[]
  results: ChainResult[]
  resultTotal: number
  offset: number
  limit: number
}

export interface ChainGridRow {
  variant: ChainVariant
  cells: ChainResult[]
  verdict: ChainVerdict
}

export interface ChainGridView {
  runId: string
  steps: ChainStepHead[]
  variants: ChainVariant[]
  rows: ChainGridRow[]
  summary: Record<string, number>
  interesting: string[]
}

export interface ChainPlan {
  variants: ChainVariant[]
  total: number
  warnings: string[]
  methods: string[]
  error?: string
}

export interface ChainRecordCandidate {
  seq: number
  method: string
  url: string
  host: string
  status: number
  contentType: string
  size: number
  timestamp: string
  label: string
}

export interface ChainPreviewStep {
  stepId: string
  label: string
  /** base64 of the rendered request, absent when the step could not render. */
  raw?: string
  missing?: ChainMissing[]
  error?: string
}

export interface ChainProposal {
  binding: ChainBinding
  isNew: boolean
  /** Why these spans cannot be accepted — set only by bind-preview. */
  conflict?: string
  note?: string
}

/** One rule that would read a chosen value out of a future response, with the
 *  proof that it reads it out of the recorded one. */
export interface ChainSourceOption {
  source: ChainSource
  detail: string
  rank: number
  matched?: string
  ok: boolean
  err?: string
}

export interface ChainBindPreviewInput {
  fromStep: string
  /** base64 — the selected bytes, which are not reliably UTF-8. */
  value: string
  occurrence?: number
  source?: ChainSource
  toSteps?: string[]
  spans?: Record<string, ChainSpan[]>
}

export interface ChainBindProposal {
  var: string
  /** base64. */
  recorded: string
  sources: ChainSourceOption[]
  proposed: ChainProposal[]
  warnings: string[] | null
}

/** A step's recorded response, decoded server-side. */
export interface ChainStepResponse {
  status: number
  /** base64 of the status line and header block, so a value in a header is
   *  selectable too — regex and between sources resolve against it. */
  headers: string
  body: string
  /** The encoding that was undone, or one it could not undo ("br (not decoded)"). */
  decoded: string
  bodyLen: number
}

/** The bag History passes through navigate() when sending a selection here. */
export interface ChainNavState {
  seqs?: number[]
  name?: string
}
