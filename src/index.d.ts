export interface PartialMaskOptions {
  keepStart?: number;
  keepEnd?: number;
  maskChar?: string;
}

export type Detector = 'jwt' | 'bearer' | 'creditCard' | 'email';

export interface RedactOptions {
  /** Extra sensitive keys (strings match ignoring case/punctuation) or RegExps. */
  keys?: Array<string | RegExp>;
  /** Ignore the built-in key list and use only `keys`. Default: false */
  replaceDefaultKeys?: boolean;
  /** Replacement text. Default: "[REDACTED]" */
  mask?: string;
  /** Keep some characters of string values under sensitive keys visible. */
  partial?: PartialMaskOptions;
  /** Value detectors applied to every string. `false` disables. Default: ['jwt','bearer','creditCard'] */
  detect?: Detector[] | false;
  /** Extra RegExps; matches inside strings are replaced with `mask`. */
  patterns?: RegExp[];
  /** Max traversal depth before "[MaxDepth]". Default: 10 */
  maxDepth?: number;
}

export interface RequestLike {
  method?: string;
  url?: string;
  originalUrl?: string;
  headers?: Record<string, unknown>;
  query?: unknown;
  params?: unknown;
  body?: unknown;
}

export function redact(input: unknown, options?: RedactOptions): any;
export function createRedactor(options?: RedactOptions): (input: unknown) => any;
export function redactString(input: string, options?: RedactOptions): string;
export function redactRequest(req: RequestLike, options?: RedactOptions): any;
export function maskValue(value: string, options?: PartialMaskOptions): string;
export const DEFAULT_SENSITIVE_KEYS: readonly string[];
