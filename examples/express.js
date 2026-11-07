'use strict';
// Run: npm i express && node examples/express.js
// Shows how to log requests without leaking credentials.
const express = require('express');
const { redactRequest } = require('../src');

const app = express();
app.use(express.json());

app.use((req, _res, next) => {
  console.log(JSON.stringify(redactRequest(req)));
  next();
});

app.post('/login', (req, res) => res.json({ ok: true }));
app.listen(3000, () => console.log('Listening on http://localhost:3000'));
