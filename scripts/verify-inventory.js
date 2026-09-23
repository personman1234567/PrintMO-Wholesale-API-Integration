const assert = require('node:assert/strict');
const fs = require('node:fs');
const test = require('node:test');
const { createSupplierInventoryHandler, normalizeInventory, parseSkus } = require('../supplier-inventory');

const sku = 'B00760004';
const supplierRow = { sku, gtin: 'private', warehouses: [{ warehouseAbbr: 'IL', skuID: 1, qty: 8 }] };
const reply = (payload, status = 200, headers = {}) => ({
  status,
  ok: status >= 200 && status < 300,
  headers: { get: name => headers[name] ?? null },
  json: async () => payload,
  body: { cancel: async () => {} },
});
function result() {
  return {
    statusCode: 200, headers: {}, body: null,
    set(name, value) { this.headers[name] = value; return this; },
    status(value) { this.statusCode = value; return this; },
    json(value) { this.body = value; return this; },
  };
}

test('gateway route is protected by the existing admin-key middleware', () => {
  const source = fs.readFileSync(require.resolve('../index'), 'utf8');
  assert.match(source, /app\.get\('\/order-manager\/v1\/supplier\/ss\/inventory', requireAdminKey, createSupplierInventoryHandler/);
});

test('only one to 25 unique supplier SKUs are accepted', () => {
  assert.deepEqual(parseSkus(sku), [sku]);
  for (const input of ['', `${sku},${sku}`, `${sku},`, 'abc def', Array(26).fill(sku).join(',')]) {
    assert.equal(parseSkus(input), null);
  }
});

test('supplier payload is reduced to exact SKU and warehouse quantity', () => {
  assert.deepEqual(normalizeInventory([supplierRow], [sku]), [{ sku, warehouses: [{ warehouseAbbr: 'IL', qty: 8 }] }]);
  for (const payload of [null, [supplierRow, supplierRow], [{ ...supplierRow, sku: 'OTHER' }],
    [{ ...supplierRow, warehouses: [{ warehouseAbbr: 'IL', qty: -1 }] }],
    [{ ...supplierRow, warehouses: [{ warehouseAbbr: 'IL', qty: '8' }] }]]) {
    assert.throws(() => normalizeInventory(payload, [sku]), /INVALID_SUPPLIER_RESPONSE/);
  }
});

test('handler makes one authenticated GET and emits no supplier extras', async () => {
  let calls = 0;
  const handler = createSupplierInventoryHandler({
    fetchImpl: async (url, options) => {
      calls++;
      assert.equal(url, `https://api.ssactivewear.com/v2/inventory/${sku}`);
      assert.equal(options.method, 'GET');
      assert.equal(options.redirect, 'error');
      assert.match(options.headers.Authorization, /^Basic /);
      return reply([supplierRow]);
    }, accountNumber: 'account', apiKey: 'secret',
  });
  const res = result();
  await handler({ query: { skus: sku } }, res);
  assert.equal(calls, 1);
  assert.equal(res.headers['Cache-Control'], 'no-store');
  assert.equal(res.statusCode, 200);
  assert.deepEqual(res.body.items, [{ sku, warehouses: [{ warehouseAbbr: 'IL', qty: 8 }] }]);
  assert.ok(Number.isFinite(Date.parse(res.body.observedAt)));
  assert.doesNotMatch(JSON.stringify(res.body), /private|secret|skuID/);
});

test('invalid requests and missing credentials never reach S&S', async () => {
  let calls = 0;
  const fetchImpl = async () => { calls++; return reply([supplierRow]); };
  const handler = createSupplierInventoryHandler({ fetchImpl, accountNumber: 'a', apiKey: 'b' });
  for (const query of [{}, { skus: `${sku},${sku}` }, { skus: sku, extra: '1' }]) {
    const res = result();
    await handler({ query }, res);
    assert.equal(res.statusCode, 400);
  }
  const missing = result();
  await createSupplierInventoryHandler({ fetchImpl })({ query: { skus: sku } }, missing);
  assert.equal(missing.statusCode, 503);
  assert.equal(calls, 0);
});

test('upstream errors do not become zero stock or leak the response body', async () => {
  const handler = createSupplierInventoryHandler({
    fetchImpl: async () => reply({ error: 'private supplier detail' }, 404), accountNumber: 'a', apiKey: 'b',
  });
  const res = result();
  await handler({ query: { skus: sku } }, res);
  assert.equal(res.statusCode, 502);
  assert.deepEqual(res.body, { error: 'UPSTREAM_HTTP_404' });
});

test('throttling retries only once and respects long Retry-After', async () => {
  let calls = 0;
  const handler = createSupplierInventoryHandler({
    fetchImpl: async () => { calls++; return reply({ error: 'private' }, 503); },
    accountNumber: 'a', apiKey: 'b', sleep: async () => {},
  });
  const res = result();
  await handler({ query: { skus: sku } }, res);
  assert.equal(calls, 2);
  assert.equal(res.body.error, 'UPSTREAM_HTTP_503');
  calls = 0;
  const deferred = createSupplierInventoryHandler({
    fetchImpl: async () => { calls++; return reply({}, 429, { 'Retry-After': '60' }); },
    accountNumber: 'a', apiKey: 'b',
  });
  const res2 = result();
  await deferred({ query: { skus: sku } }, res2);
  assert.equal(calls, 1);
  assert.equal(res2.body.error, 'UPSTREAM_RETRY_DEFERRED');
});
