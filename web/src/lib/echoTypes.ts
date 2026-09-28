// Types for the Echo tab: the reflection map. Mirrors internal/echo's model.
// Verdicts are server-side — this file carries the vocabulary the server sends
// and the labels to render it with, never the rubric that decides a breakout.

export type EchoSource =
  | 'query' | 'path' | 'form' | 'json' | 'multipart' | 'header' | 'cookie'

export type EchoTransform =
  | 'identity' | 'percent' | 'html_entity' | 'js_string' | 'base64'
  | 'percent+html_entity' | 'percent+percent' | 'html_entity+percent'

export type EchoContext =
  | 'html_text' | 'html_comment' | 'tag_name' | 'attr_name' | 'attr_value'
  | 'script' | 'style' | 'json_string' | 'json_key' | 'header_value' | 'plain'

export type EchoJSContext =
  | 'code' | 'string_single' | 'string_double' | 'template' | 'comment' | ''

export type EchoConfidence = 'high' | 'medium' | 'low'

export interface EchoSpan {
  start: number
  end: number
}

export interface EchoReflection {
  source: EchoSource
  name: string
  value: string
  transform: EchoTransform
  context: EchoContext
  jsContext?: EchoJSContext
  attr?: string
  quote?: string
  /** Which document the span indexes: 'request' or 'response'. */
  part: string
  /**
   * Which coordinate system the span uses. 'raw' indexes the document the
   * viewer renders; 'decoded-body' indexes the decompressed body instead,
   * because a gzip'd response shares no offsets with its raw bytes.
   */
  coord: 'raw' | 'decoded-body'
  span: EchoSpan
  /** The value's own metacharacters that reached the response literally. */
  survived?: string
  breakout: boolean
  confidence: EchoConfidence
}

export interface EchoSink {
  context: EchoContext
  jsContext?: EchoJSContext
  transform: EchoTransform
  attr?: string
  count: number
  breakout: boolean
}

/** EchoEntry is one row of the map: a parameter on a host, and where it lands. */
export interface EchoEntry {
  id: string
  host: string
  source: EchoSource
  name: string
  observations: number
  distinctValues: number
  reflections: number
  breakouts: number
  sinks: EchoSink[]
  lastSeen: string
  exampleRequestId: string
  exampleUrl: string
  exampleValue: string
  examples?: EchoReflection[]
}

/** EchoValue is one input a request carried, as the walker enumerated it. */
export interface EchoValue {
  source: EchoSource
  name: string
  value: string
  span: EchoSpan
}

export interface EchoRequestParams {
  requestId: string
  params: EchoValue[]
  truncated: boolean
}

/**
 * EchoParamRow is one row of the parameter inventory: a parameter observed at a
 * site-map node, independent of whether it ever came back in a response.
 *
 * `reflected` false means reflection mapping has not seen it come back, which
 * includes the case where mapping has never run at all. It is not a finding that
 * the parameter does not reflect.
 */
export interface EchoParamRow {
  source: EchoSource
  name: string
  requests: number
  distinctValues: number
  methods: string[]
  exampleValue: string
  exampleRequestId: string
  lastSeen: string
  reflected: boolean
  breakouts: number
}

export interface EchoInventory {
  origin: string
  path: string
  requests: number
  walked: number
  truncated: boolean
  params: EchoParamRow[]
}

export interface EchoReport {
  requestId: string
  seq: number
  host: string
  method: string
  url: string
  timestamp: string
  values: number
  needles: number
  breakouts: number
  reflections: EchoReflection[]
  truncated: boolean
}

export interface EchoConfig {
  enabled: boolean
  scopeOnly: boolean
  maxBodyScanBytes: number
  maxRequestBodyScanBytes: number
  minValueLen: number
  maxValuesPerRequest: number
  maxReflectionsPerRequest: number
  transformDepth: number
  base64: boolean
  scanHeaders: boolean
  excludeHosts?: string[]
}

export interface EchoSummary {
  params: number
  hosts: number
  reflections: number
  breakouts: number
  scanned: number
  byContext: Record<string, number>
  byTransform: Record<string, number>
}

export interface EchoScanStatus {
  running: boolean
  jobId?: string
  scanned: number
  total: number
  status?: string
}

export interface EchoState {
  enabled: boolean
  config: EchoConfig
  summary: EchoSummary
  hosts: string[]
  scan: EchoScanStatus
}

export interface EchoFilter {
  host: string
  sources: EchoSource[]
  contexts: EchoContext[]
  transforms: EchoTransform[]
  breakoutOnly: boolean
  search: string
}

export const EMPTY_ECHO_FILTER: EchoFilter = {
  host: '',
  sources: [],
  contexts: [],
  transforms: [],
  breakoutOnly: false,
  search: '',
}

/** Display labels. Rendering only; the server decides what a sink means. */
export const CONTEXT_LABELS: Record<EchoContext, string> = {
  html_text: 'HTML text',
  html_comment: 'HTML comment',
  tag_name: 'Tag name',
  attr_name: 'Attribute name',
  attr_value: 'Attribute value',
  script: 'Script',
  style: 'Stylesheet',
  json_string: 'JSON string',
  json_key: 'JSON key',
  header_value: 'Response header',
  plain: 'Plain text',
}

export const TRANSFORM_LABELS: Record<string, string> = {
  identity: 'Raw',
  percent: 'URL-encoded',
  html_entity: 'HTML-encoded',
  js_string: 'JS-escaped',
  base64: 'Base64',
  'percent+html_entity': 'URL + HTML',
  'percent+percent': 'Double URL',
  'html_entity+percent': 'HTML + URL',
}

export const SOURCE_LABELS: Record<EchoSource, string> = {
  query: 'Query',
  path: 'Path',
  form: 'Form',
  json: 'JSON',
  multipart: 'Multipart',
  header: 'Header',
  cookie: 'Cookie',
}

export const CONTEXT_OPTIONS = Object.keys(CONTEXT_LABELS) as EchoContext[]
export const TRANSFORM_OPTIONS = Object.keys(TRANSFORM_LABELS) as EchoTransform[]
export const SOURCE_OPTIONS = Object.keys(SOURCE_LABELS) as EchoSource[]

/** describeSink renders one sink as a short phrase for a row. */
export function describeSink(s: EchoSink): string {
  const ctx =
    s.context === 'attr_value' && s.attr
      ? `${s.attr} attribute`
      : s.context === 'script' && s.jsContext && s.jsContext !== 'code'
        ? `script ${s.jsContext.replace('_', ' ')}`
        : CONTEXT_LABELS[s.context] ?? s.context
  return `${TRANSFORM_LABELS[s.transform] ?? s.transform} in ${ctx}`
}
