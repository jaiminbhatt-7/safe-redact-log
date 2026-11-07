'use strict';
const { redact, createRedactor, redactString, maskValue } = require('../src');

console.log('--- 1. Basic object ---');
console.log(redact({
  user: 'alice',
  password: 'hunter2',
  headers: { Authorization: 'Bearer abc.def.ghi', 'X-API-Key': 'k_123' },
}));

console.log('--- 2. Partial masking (keep last 4) ---');
console.log(redact({ cardNumber: '4111111111111111' }, { partial: { keepEnd: 4 } }));

console.log('--- 3. Reusable redactor with custom keys ---');
const safe = createRedactor({ keys: ['nationalId', /^internal_/], detect: ['jwt', 'email'] });
console.log(safe({ nationalId: '99-111', internal_note: 'x', contact: 'bob@example.com' }));

console.log('--- 4. Free-text strings ---');
console.log(redactString('User paid with 4111 1111 1111 1111, auth Bearer xyz123'));

console.log('--- 5. Errors and circular refs ---');
const err = new Error('Upstream rejected Bearer s3cr3t');
const loop = { name: 'loop', err };
loop.self = loop;
console.log(redact(loop));

console.log('--- 6. maskValue ---');
console.log(maskValue('9876543210', { keepStart: 2, keepEnd: 2 }));
