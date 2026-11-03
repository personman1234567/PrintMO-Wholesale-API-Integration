'use strict';

// Test-only adapter: register the actual production commit handler without starting
// the production app, connecting Redis, or obtaining any supplier credentials.
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const express = require('express');
const { submitSsOrder } = require('../../supplier-order-submit');

const fixtureGatewayKey = 'synthetic-gateway-key';
function createSupplierCommitFixture({ nativeFetch, now = Date.now }) {
  if (typeof nativeFetch !== 'function') throw new TypeError('A mocked nativeFetch is required.');
  const app = express();
  app.use(express.json());
  const source = fs.readFileSync(path.join(__dirname, '../../index.js'), 'utf8');
  const start = source.indexOf("app.post('/order-manager/v1/supplier/ss/commit'");
  const end = source.indexOf('\nconst phase2Data =', start);
  if (start < 0 || end < start) throw new Error('Production commit handler boundary changed.');
  const env = { SS_ACCOUNT_NUMBER: 'synthetic-account', SS_API_KEY: 'synthetic-key',
    SS_PAYMENT_PROFILE_ID: '123', SS_PAYMENT_PROFILE_EMAIL: 'fixture@example.test' };
  vm.runInNewContext(source.slice(start, end), {
    app,
    requireAdminKey: (request, response, next) => request.get('X-Order-Manager-Key') === fixtureGatewayKey
      ? next() : response.status(401).json({ error: 'Unauthorized fixture request' }),
    submitSsOrder: options => submitSsOrder(options, { env, fetchImpl: nativeFetch, now }),
    console: { error() {} },
  }, { filename: 'actual-supplier-commit-handler.fixture.js' });
  return app;
}

module.exports = { createSupplierCommitFixture, fixtureGatewayKey };
