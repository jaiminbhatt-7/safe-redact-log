'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const {
  redact, createRedactor, redactString, redactRequest, maskValue, DEFAULT_SENSITIVE_KEYS,
} = require('../src');

test('masks default sensitive keys, ignoring case and punctuation', () => {
  const out = redact({ Password: 'a', api_key: 'b', 'X-API-Key': 'c', user: 'bob' });
  assert.deepEqual(out, {
    Password: '[REDACTED]', api_key: '[REDACTED]', 'X-API-Key': '[REDACTED]', user: 'bob',
  });
});

test('redacts nested objects and arrays', () => {
  const out = redact({ a: [{ token: 't', ok: 1 }], b: { c: { secret: 's' } } });
  assert.deepEqual(out, { a: [{ token: '[REDACTED]', ok: 1 }], b: { c: { secret: '[REDACTED]' } } });
});

test('does not mutate the input', () => {
  const input = { password: 'x', nested: { token: 'y' } };
  const snapshot = JSON.parse(JSON.stringify(input));
  redact(input);
  assert.deepEqual(input, snapshot);
});

test('sensitive key with object value is fully masked', () => {
  assert.deepEqual(redact({ secret: { a: 1 } }), { secret: '[REDACTED]' });
});

test('custom keys (string and RegExp) and replaceDefaultKeys', () => {
  const out = redact({ nickname: 'n', internal_x: 1, password: 'p' }, { keys: ['nickname', /^internal_/] });
  assert.equal(out.nickname, '[REDACTED]');
  assert.equal(out.internal_x, '[REDACTED]');
  assert.equal(out.password, '[REDACTED]');
  const only = redact({ nickname: 'n', password: 'p' }, { keys: ['nickname'], replaceDefaultKeys: true });
  assert.equal(only.password, 'p');
  assert.equal(only.nickname, '[REDACTED]');
});

test('custom mask and partial masking', () => {
  assert.equal(redact({ token: 'abc' }, { mask: '***' }).token, '***');
  assert.equal(redact({ cardNumber: '4111111111111111' }, { partial: { keepEnd: 4 } }).cardNumber, '************1111');
});

test('detects JWTs, bearer tokens and Luhn-valid cards inside strings', () => {
  const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc123_-xyz';
  assert.equal(redactString(`tok ${jwt} end`), 'tok [REDACTED] end');
  assert.equal(redactString('Authorization: Bearer abc.def-123'), 'Authorization: Bearer [REDACTED]');
  assert.equal(redactString('card 4111 1111 1111 1111 ok'), 'card [REDACTED] ok');
});

test('does not redact digit strings failing the Luhn check', () => {
  assert.equal(redactString('order 1234567890123456'), 'order 1234567890123456');
});

test('email detection is opt-in', () => {
  assert.equal(redactString('mail a@b.com'), 'mail a@b.com');
  assert.equal(redactString('mail a@b.com', { detect: ['email'] }), 'mail [REDACTED]');
});

test('detect: false disables value detectors', () => {
  assert.equal(redactString('Bearer abc', { detect: false }), 'Bearer abc');
});

test('custom patterns work with or without the g flag', () => {
  assert.equal(redactString('id SSN-123 and SSN-456', { patterns: [/SSN-\d+/] }), 'id [REDACTED] and [REDACTED]');
});

test('handles circular references', () => {
  const a = { name: 'a' };
  a.self = a;
  assert.deepEqual(redact(a), { name: 'a', self: '[Circular]' });
});

test('shared (non-circular) references are preserved', () => {
  const shared = { v: 1 };
  assert.deepEqual(redact({ x: shared, y: shared }), { x: { v: 1 }, y: { v: 1 } });
});

test('respects maxDepth', () => {
  const out = redact({ a: { b: { c: 1 } } }, { maxDepth: 2 });
  assert.deepEqual(out, { a: { b: '[MaxDepth]' } });
});

test('handles Error, Date, Map, Set, Buffer, functions', () => {
  const err = new Error('failed with Bearer abc123');
  err.password = 'pw';
  const out = redact({
    err, d: new Date(0), m: new Map([['token', 'x'], ['k', 'v']]),
    s: new Set(['Bearer zzz']), b: Buffer.from('hi'), f() {},
  });
  assert.equal(out.err.message, 'failed with Bearer [REDACTED]');
  assert.equal(out.err.password, '[REDACTED]');
  assert.equal(out.d.getTime(), 0);
  assert.equal(out.m.get('token'), '[REDACTED]');
  assert.equal(out.m.get('k'), 'v');
  assert.ok(out.s.has('Bearer [REDACTED]'));
  assert.equal(out.b, '[Buffer]');
  assert.equal(out.f, '[Function]');
});

test('passes through primitives, null and undefined', () => {
  assert.equal(redact(5), 5);
  assert.equal(redact(null), null);
  assert.equal(redact(undefined), undefined);
  assert.equal(redact(true), true);
});

test('createRedactor reuses configuration', () => {
  const r = createRedactor({ keys: ['foo'] });
  assert.equal(r({ foo: 1 }).foo, '[REDACTED]');
  assert.equal(r({ foo: 2 }).foo, '[REDACTED]');
});

test('redactRequest builds a safe summary', () => {
  const out = redactRequest({
    method: 'POST', originalUrl: '/login',
    headers: { authorization: 'Bearer abc', accept: 'json' },
    body: { user: 'bob', password: 'pw' },
  });
  assert.equal(out.url, '/login');
  assert.equal(out.headers.authorization, '[REDACTED]');
  assert.equal(out.headers.accept, 'json');
  assert.equal(out.body.password, '[REDACTED]');
});

test('maskValue behaviour and validation', () => {
  assert.equal(maskValue('secret'), '******');
  assert.equal(maskValue('secret', { keepStart: 1, keepEnd: 2 }), 's***et');
  assert.equal(maskValue('ab', { keepEnd: 4 }), '**');
  assert.throws(() => maskValue('x', { keepEnd: -1 }), RangeError);
});

test('invalid options throw helpful errors', () => {
  assert.throws(() => redact({}, { detect: ['nope'] }), TypeError);
  assert.throws(() => redact({}, { keys: [1] }), TypeError);
  assert.throws(() => redact({}, { maxDepth: 0 }), RangeError);
  assert.throws(() => redact({}, { patterns: ['x'] }), TypeError);
});

test('DEFAULT_SENSITIVE_KEYS is frozen', () => {
  assert.ok(Object.isFrozen(DEFAULT_SENSITIVE_KEYS));
});
