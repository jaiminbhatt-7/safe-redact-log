# safe-redact-log

[![npm version](https://img.shields.io/npm/v/safe-redact-log.svg)](https://www.npmjs.com/package/safe-redact-log)
[![CI](https://github.com/jaiminbhatt-7/safe-redact-log/actions/workflows/ci.yml/badge.svg)](https://github.com/jaiminbhatt-7/safe-redact-log/actions)
[![license](https://img.shields.io/npm/l/safe-redact-log.svg)](LICENSE)

> Zero-dependency deep redaction of secrets and PII, so objects, errors and HTTP requests are **safe to log**.

## What it does

`safe-redact-log` takes any JavaScript value (objects, arrays, errors, Maps, Sets…), returns a **sanitised deep copy**, and never mutates your original data. It masks:

- **Sensitive keys** – `password`, `token`, `apiKey`, `Authorization`, `cookie`, `cvv`, … (case- and punctuation-insensitive: `api_key`, `API-Key` and `apiKey` all match).
- **Sensitive values inside strings** – JWTs, `Bearer` tokens, Luhn-valid credit-card numbers, and (optionally) emails or your own RegExps.

## Why it is useful

Accidentally logging `req.body` or `error.config.headers` is one of the most common causes of credential leaks (OWASP A09: Security Logging Failures). Existing logger plugins are tied to one logger; this package is logger-agnostic and works with `console`, Winston, Pino, Bunyan, or anything that accepts an object. It also handles the awkward cases that make naive `JSON.stringify` replacers fail: circular references, `Error` objects, `Map`/`Set`, deep nesting, and secrets embedded in free-text.

## Installation

```bash
npm install safe-redact-log
```

Requires Node.js **>= 18**. Ships with TypeScript types. No runtime dependencies.

## Quick start

```js
const { redact } = require('safe-redact-log');

const safe = redact({
  user: 'alice',
  password: 'hunter2',
  headers: { Authorization: 'Bearer abc.def.ghi' },
});

console.log(safe);
// { user: 'alice', password: '[REDACTED]', headers: { Authorization: '[REDACTED]' } }
```

ES module / TypeScript:

```ts
import { redact, createRedactor } from 'safe-redact-log';
```

## API

### `redact(input, [options])` → `any`
Returns a redacted deep copy of `input`.

| Param | Type | Description |
|---|---|---|
| `input` | `any` | Value to sanitise. Primitives are returned unchanged (strings pass through value detectors). |
| `options` | `RedactOptions` | See [Options](#options). |

### `createRedactor([options])` → `(input) => any`
Validates and compiles options once and returns a reusable function. Prefer this for hot logging paths.

### `redactString(text, [options])` → `string`
Applies only the value detectors (JWT, Bearer, credit card, email, custom patterns) to free text.

### `redactRequest(req, [options])` → `object`
Builds a log-safe summary `{ method, url, headers, query, params, body }` from an Express/Node-style request.

### `maskValue(value, [opts])` → `string`
Masks a string, optionally keeping characters visible.

| Param | Default | Description |
|---|---|---|
| `opts.keepStart` | `0` | Leading characters to keep |
| `opts.keepEnd` | `0` | Trailing characters to keep |
| `opts.maskChar` | `'*'` | Masking character |

Throws `RangeError` if `keepStart`/`keepEnd` are negative. Strings too short to reveal anything are fully masked.

### `DEFAULT_SENSITIVE_KEYS`
Frozen array of the built-in normalised key names.

### Options

| Option | Type | Default | Description |
|---|---|---|---|
| `keys` | `(string \| RegExp)[]` | `[]` | Extra sensitive keys. Strings are matched ignoring case and punctuation; RegExps are tested against the raw key. |
| `replaceDefaultKeys` | `boolean` | `false` | Use only your `keys`, not the built-ins. |
| `mask` | `string` | `'[REDACTED]'` | Replacement text. |
| `partial` | `{keepStart?, keepEnd?, maskChar?}` | – | Keep part of **string** values under sensitive keys visible (e.g. last 4 card digits). |
| `detect` | `('jwt'\|'bearer'\|'creditCard'\|'email')[] \| false` | `['jwt','bearer','creditCard']` | Value detectors run on every string. `false` disables. |
| `patterns` | `RegExp[]` | `[]` | Extra patterns; matches are replaced with `mask`. |
| `maxDepth` | `number` | `10` | Deeper values become `'[MaxDepth]'`. |

Invalid options throw `TypeError`/`RangeError` immediately with a descriptive message.

## Examples

**Partial masking**
```js
redact({ cardNumber: '4111111111111111' }, { partial: { keepEnd: 4 } });
// { cardNumber: '************1111' }
```

**Custom keys, RegExps and emails**
```js
const safe = createRedactor({ keys: ['nationalId', /^internal_/], detect: ['jwt', 'email'] });
safe({ nationalId: '99-111', internal_note: 'x', contact: 'bob@example.com' });
// { nationalId: '[REDACTED]', internal_note: '[REDACTED]', contact: '[REDACTED]' }
```

**Free-text and errors**
```js
redactString('paid with 4111 1111 1111 1111, auth Bearer xyz');
// 'paid with [REDACTED], auth Bearer [REDACTED]'

redact(new Error('Upstream rejected Bearer s3cr3t'));
// { name: 'Error', message: 'Upstream rejected Bearer [REDACTED]', stack: '...' }
```

**Express request logging** (see [`examples/express.js`](examples/express.js))
```js
app.use((req, _res, next) => {
  console.log(JSON.stringify(redactRequest(req)));
  next();
});
```

**With Pino / Winston**
```js
const log = (obj, msg) => logger.info(redact(obj), msg);
```

Run the full demo: `npm run example`.

## Behaviour notes

- Input is **never mutated**; Dates are cloned; functions become `'[Function]'`; Buffers become `'[Buffer]'`.
- Circular references become `'[Circular]'`. Shared (non-circular) references are preserved.
- A sensitive key whose value is an object/array is replaced entirely by the mask.
- `Error` objects are converted to plain objects (`name`, `message`, `stack` + own enumerable props).

## Limitations

- Redaction is **heuristic**. Secrets with unusual key names or formats won't be found unless you add `keys`/`patterns`. Treat this as a safety net, not a guarantee.
- Only own enumerable string-keyed properties are traversed (no Symbol keys, getters on prototypes, or non-enumerable props).
- Credit-card detection requires 13–19 digits passing the Luhn check, so some fake/test numbers will not match.
- Very large objects are copied, so there is a CPU/memory cost; reuse `createRedactor` and lower `maxDepth` if needed.

## Testing

```bash
npm test               # run the test suite (node:test, no dev dependencies)
npm run test:coverage  # with coverage report
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Issues and PRs are welcome.

## License

[MIT](LICENSE)
