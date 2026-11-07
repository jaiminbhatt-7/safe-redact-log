'use strict';

/**
 * safe-redact-log
 * Zero-dependency utility that deep-clones data and masks sensitive
 * keys and values so it is safe to log.
 */

const DEFAULT_SENSITIVE_KEYS = Object.freeze([
  'password', 'passwd', 'pwd', 'passphrase',
  'secret', 'clientsecret',
  'token', 'accesstoken', 'refreshtoken', 'idtoken', 'authtoken',
  'apikey', 'xapikey',
  'authorization', 'proxyauthorization',
  'cookie', 'setcookie',
  'creditcard', 'cardnumber', 'cvv', 'cvc',
  'ssn', 'privatekey',
]);

const DEFAULT_MASK = '[REDACTED]';
const DEFAULT_DETECTORS = Object.freeze(['jwt', 'bearer', 'creditCard']);
const VALID_DETECTORS = ['jwt', 'bearer', 'creditCard', 'email'];

/** Lowercase and strip non-alphanumerics: "X-API-Key" -> "xapikey". */
function normalizeKey(key) {
  return String(key).toLowerCase().replace(/[^a-z0-9]/g, '');
}

function luhnValid(digits) {
  let sum = 0;
  let double = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (double) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    double = !double;
  }
  return sum % 10 === 0;
}

/**
 * Mask a string, optionally keeping the first/last characters visible.
 * @param {string} value
 * @param {{keepStart?: number, keepEnd?: number, maskChar?: string}} [opts]
 * @returns {string}
 */
function maskValue(value, opts = {}) {
  const { keepStart = 0, keepEnd = 0, maskChar = '*' } = opts;
  const str = String(value);
  if (keepStart < 0 || keepEnd < 0) {
    throw new RangeError('keepStart and keepEnd must be >= 0');
  }
  if (str.length <= keepStart + keepEnd) return maskChar.repeat(str.length);
  return (
    str.slice(0, keepStart) +
    maskChar.repeat(str.length - keepStart - keepEnd) +
    (keepEnd ? str.slice(str.length - keepEnd) : '')
  );
}

function resolveConfig(options) {
  if (options === null || typeof options !== 'object') options = {};

  const keyStrings = new Set(options.replaceDefaultKeys ? [] : DEFAULT_SENSITIVE_KEYS);
  const keyRegexes = [];
  for (const k of options.keys || []) {
    if (k instanceof RegExp) keyRegexes.push(k);
    else if (typeof k === 'string') keyStrings.add(normalizeKey(k));
    else throw new TypeError('options.keys must contain strings or RegExps');
  }

  const detectors = options.detect === false ? [] : options.detect || DEFAULT_DETECTORS;
  for (const d of detectors) {
    if (!VALID_DETECTORS.includes(d)) {
      throw new TypeError(`Unknown detector "${d}". Valid: ${VALID_DETECTORS.join(', ')}`);
    }
  }

  const customPatterns = options.patterns || [];
  for (const p of customPatterns) {
    if (!(p instanceof RegExp)) throw new TypeError('options.patterns must contain RegExps');
  }

  const maxDepth = options.maxDepth === undefined ? 10 : options.maxDepth;
  if (!Number.isInteger(maxDepth) || maxDepth < 1) {
    throw new RangeError('options.maxDepth must be a positive integer');
  }

  return {
    keyStrings,
    keyRegexes,
    detectors,
    customPatterns,
    mask: options.mask === undefined ? DEFAULT_MASK : String(options.mask),
    partial: options.partial || null,
    maxDepth,
  };
}

function isSensitiveKey(key, cfg) {
  if (typeof key !== 'string') return false;
  if (cfg.keyStrings.has(normalizeKey(key))) return true;
  for (const re of cfg.keyRegexes) {
    re.lastIndex = 0;
    if (re.test(key)) return true;
  }
  return false;
}

function maskForKey(value, cfg) {
  if (cfg.partial && typeof value === 'string') return maskValue(value, cfg.partial);
  return cfg.mask;
}

function redactStringWith(str, cfg) {
  let out = str;
  if (cfg.detectors.includes('jwt')) {
    out = out.replace(/\beyJ[\w-]+\.[\w-]+\.[\w-]+\b/g, cfg.mask);
  }
  if (cfg.detectors.includes('bearer')) {
    out = out.replace(/\b(Bearer\s+)[\w\-.~+/]+=*/gi, (_m, prefix) => prefix + cfg.mask);
  }
  if (cfg.detectors.includes('creditCard')) {
    out = out.replace(/\b(?:\d[ -]?){12,18}\d\b/g, (match) => {
      const digits = match.replace(/[ -]/g, '');
      return digits.length >= 13 && digits.length <= 19 && luhnValid(digits) ? cfg.mask : match;
    });
  }
  if (cfg.detectors.includes('email')) {
    out = out.replace(/[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+/g, cfg.mask);
  }
  for (const re of cfg.customPatterns) {
    const flags = re.flags.includes('g') ? re.flags : re.flags + 'g';
    out = out.replace(new RegExp(re.source, flags), cfg.mask);
  }
  return out;
}

function walk(value, cfg, depth, ancestors) {
  if (typeof value === 'string') return redactStringWith(value, cfg);
  if (value === null || typeof value !== 'object') {
    return typeof value === 'function' ? '[Function]' : value;
  }
  if (depth >= cfg.maxDepth) return '[MaxDepth]';
  if (ancestors.has(value)) return '[Circular]';
  if (value instanceof Date) return new Date(value.getTime());
  if (typeof Buffer !== 'undefined' && Buffer.isBuffer(value)) return '[Buffer]';

  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      return value.map((v) => walk(v, cfg, depth + 1, ancestors));
    }
    if (value instanceof Set) {
      return new Set([...value].map((v) => walk(v, cfg, depth + 1, ancestors)));
    }
    if (value instanceof Map) {
      const out = new Map();
      for (const [k, v] of value) {
        out.set(k, isSensitiveKey(k, cfg) ? maskForKey(v, cfg) : walk(v, cfg, depth + 1, ancestors));
      }
      return out;
    }

    const out = {};
    if (value instanceof Error) {
      out.name = value.name;
      out.message = redactStringWith(value.message, cfg);
      if (value.stack) out.stack = redactStringWith(value.stack, cfg);
    }
    for (const key of Object.keys(value)) {
      out[key] = isSensitiveKey(key, cfg)
        ? maskForKey(value[key], cfg)
        : walk(value[key], cfg, depth + 1, ancestors);
    }
    return out;
  } finally {
    ancestors.delete(value);
  }
}

/**
 * Create a reusable redact function with fixed options.
 * @param {object} [options]
 * @returns {(input: any) => any}
 */
function createRedactor(options) {
  const cfg = resolveConfig(options);
  return function redact(input) {
    return walk(input, cfg, 0, new WeakSet());
  };
}

/**
 * One-off redaction. Returns a sanitised deep copy; input is never mutated.
 * @param {any} input
 * @param {object} [options]
 */
function redact(input, options) {
  return createRedactor(options)(input);
}

/**
 * Redact only the text content of a string using value detectors.
 * @param {string} input
 * @param {object} [options]
 */
function redactString(input, options) {
  return redactStringWith(String(input), resolveConfig(options));
}

/**
 * Build a log-safe summary of an HTTP request (Express/Node compatible).
 * @param {object} req
 * @param {object} [options]
 */
function redactRequest(req, options) {
  const r = createRedactor(options);
  return r({
    method: req.method,
    url: req.originalUrl || req.url,
    headers: req.headers || {},
    query: req.query || {},
    params: req.params || {},
    body: req.body,
  });
}

module.exports = {
  redact,
  createRedactor,
  redactString,
  redactRequest,
  maskValue,
  DEFAULT_SENSITIVE_KEYS,
};
