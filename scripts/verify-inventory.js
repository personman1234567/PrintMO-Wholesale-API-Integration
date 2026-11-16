const assert = require('node:assert/strict');
const fs = require('node:fs');
const test = require('node:test');
const { createSupplierInventoryHandler, createSupplierInventoryReader, normalizeProducts, parseSkus, CACHE_TTL_MS } = require('../supplier-inventory');
const { createInventoryReadAuth } = require('../inventory-auth');
const sku = 'B00760004';
const row = (sku, qty = 8) => ({ sku, privateField: 'private', warehouses: [
  { warehouseAbbr: 'IL', qty, dropship: false }, { warehouseAbbr: 'DS', qty: 99, dropship: true }] });
const reply = (payload, status = 200, headers = {}) => ({ status, ok: status >= 200 && status < 300,
  headers: new Headers(headers), json: async () => payload, body: { cancel: async () => {} } });
function result() {
  return { statusCode: 200, headers: {}, body: null,
    set(name, value) { this.headers[name] = value; return this; },
    status(value) { this.statusCode = value; return this; }, json(value) { this.body = value; return this; } };
}
function fixture(fetchImpl) {
  let current = Date.UTC(2026, 10, 14, 12, 0, 0);
  const waits = [], calls = [];
  const options = { accountNumber: 'account', apiKey: 'secret', now: () => current,
    sleep: async ms => { waits.push(ms); current += ms; },
    fetchImpl: async (url, options) => { calls.push({ url, options, at: current });
      const skus = new URL(url).pathname.split('/').at(-1).split(',');
      return fetchImpl ? fetchImpl(skus, calls.length) : reply(skus.map(sku => row(sku)));
    } };
  return { options, calls, waits, advance: ms => { current += ms; }, now: () => current };
}
test('gateway route uses a scoped key when configured and preserves staged fallback', () => {
  const source = fs.readFileSync(require.resolve('../index'), 'utf8');
  assert.match(source, /app\.get\('\/order-manager\/v1\/supplier\/ss\/inventory', requireInventoryReadKey, createSupplierInventoryHandler/);
  function invoke(auth, headers = {}) {
    let called = false;
    const res = result();
    auth({ method: 'GET', get: name => headers[name] }, res, () => { called = true; });
    return { called, status: res.statusCode };
  }
  const scoped = createInventoryReadAuth({ inventoryReadKey: 'inventory-only', adminKey: 'admin-wide' });
  assert.deepEqual(invoke(scoped, { 'X-Inventory-Read-Key': 'inventory-only' }), { called: true, status: 200 });
  assert.deepEqual(invoke(scoped, { 'X-Order-Manager-Key': 'admin-wide' }), { called: false, status: 401 });
  assert.deepEqual(invoke(scoped, { 'X-Inventory-Read-Key': 'wrong' }), { called: false, status: 401 });
  const staged = createInventoryReadAuth({ adminKey: 'admin-wide' });
  assert.deepEqual(invoke(staged, { 'X-Order-Manager-Key': 'admin-wide' }), { called: true, status: 200 });
  assert.deepEqual(invoke(createInventoryReadAuth({})), { called: false, status: 500 });
});


test('accepts one to 250 unique SKUs, rejecting excess, duplicate and malformed input', () => {
  assert.deepEqual(parseSkus(sku), [sku]);
  assert.equal(parseSkus(Array.from({ length: 250 }, (_, i) => 'B' + i).join(',')).length, 250);
  for (const input of ['', sku + ',' + sku, sku + ',', 'abc def', Array.from({ length: 251 }, (_, i) => 'B' + i).join(',')]) assert.equal(parseSkus(input), null);
});
test('products normalizer keeps only exact validated SKU, quantity and dropship evidence', () => {
  assert.deepEqual(normalizeProducts([row(sku)], [sku]), [{ sku, warehouses: row(sku).warehouses }]);
  for (const payload of [null, [row(sku), row(sku)], [row('OTHER')], [{ ...row(sku), warehouses: [] }],
    ...[-1, '8', null, 1.5].map(qty => [{ ...row(sku), warehouses: [{ warehouseAbbr: 'IL', qty, dropship: false }] }]),
    [{ ...row(sku), warehouses: [{ warehouseAbbr: 'IL', qty: 8 }] }]]) assert.throws(() => normalizeProducts(payload, [sku]), /INVALID_SUPPLIER_RESPONSE/);
  assert.deepEqual(normalizeProducts([], [sku]), []);
});
test('repeated DS rows collapse only with valid quantities and all flags true; physical duplicates fail', () => {
  const repeated = { ...row(sku), warehouses: [...row(sku).warehouses, { warehouseAbbr: 'DS', qty: 12, dropship: true }] };
  assert.deepEqual(normalizeProducts([repeated], [sku]), normalizeProducts([row(sku)], [sku]));
  for (const duplicate of [{ warehouseAbbr: 'DS', qty: 12, dropship: false }, { warehouseAbbr: 'DS', qty: null, dropship: true },
    { warehouseAbbr: 'IL', qty: 12, dropship: false }, { warehouseAbbr: 'IL', qty: 12, dropship: true }]) {
    assert.throws(() => normalizeProducts([{ ...row(sku), warehouses: [...row(sku).warehouses, duplicate] }], [sku]), /INVALID_SUPPLIER_RESPONSE/);
  }
});
test('250-SKU handler makes one authenticated products GET and emits no supplier extras', async () => {
  const f = fixture(), handler = createSupplierInventoryHandler(f.options), res = result();
  const skus = Array.from({ length: 250 }, (_, i) => 'B' + i);
  await handler({ query: { skus: skus.join(',') } }, res);
  assert.equal(f.calls.length, 1); assert.equal(res.statusCode, 200); assert.equal(res.body.items.length, 250);
  assert.equal(f.calls[0].options.method, 'GET'); assert.equal(f.calls[0].options.redirect, 'error');
  assert.match(f.calls[0].options.headers.Authorization, /^Basic /);
  assert.equal(new URL(f.calls[0].url).searchParams.get('fields'), 'sku,styleID,warehouses,customerPrice');
  assert.equal(res.headers['Cache-Control'], 'no-store');
  assert.doesNotMatch(JSON.stringify(res.body), /private|secret|account/);
});
test('cache timestamp is the start of the real fetch and is never renewed on a hit', async () => {
  const f = fixture(async skus => { f.advance(1000); return reply(skus.map(sku => row(sku))); });
  const read = createSupplierInventoryReader(f.options), started = f.now();
  const first = await read([sku]); f.advance(30000); const second = await read([sku]);
  assert.equal(first.observedAt, new Date(started).toISOString()); assert.equal(second.observedAt, first.observedAt); assert.equal(f.calls.length, 1);
});
test('mixed-age cache response preserves the oldest observation and fetches only missing SKUs', async () => {
  const f = fixture(), read = createSupplierInventoryReader(f.options);
  const first = await read(['OLD']); f.advance(10000); const mixed = await read(['OLD', 'NEW']);
  assert.equal(mixed.observedAt, first.observedAt); assert.match(f.calls[1].url, /products\/NEW\?/); assert.equal(mixed.items.length, 2);
});
test('expired cache refetches and failed refresh never serves stale stock or caches an error', async () => {
  const f = fixture((skus, n) => n === 2 ? reply({ private: 'detail' }, 502) : reply(skus.map(sku => row(sku, n))));
  const read = createSupplierInventoryReader(f.options); const first = await read([sku]); f.advance(CACHE_TTL_MS);
  await assert.rejects(read([sku]), /UPSTREAM_HTTP_502/);
  const third = await read([sku]); assert.notEqual(third.observedAt, first.observedAt); assert.equal(third.items[0].warehouses[0].qty, 3); assert.equal(f.calls.length, 3);
});
test('overlapping concurrent cache fills are coalesced and 25-SKU slices reuse a 250-SKU fill', async () => {
  const f = fixture(), read = createSupplierInventoryReader(f.options), skus = Array.from({ length: 250 }, (_, i) => 'B' + i);
  const results = await Promise.all([read(skus), read(skus.slice(0,25)), read(skus.slice(25,50))]);
  assert.equal(f.calls.length, 1); assert.equal(results[1].items.length,25); assert.equal(results[2].observedAt,results[0].observedAt);
});
test('successful omissions stay absent on cache hits, without invented zero rows', async () => {
  const f = fixture(() => reply([])), read = createSupplierInventoryReader(f.options);
  const first = await read([sku]); f.advance(1000); const second = await read([sku]);
  assert.deepEqual(second.items,[]); assert.equal(first.observedAt,second.observedAt); assert.equal(f.calls.length,1);
});
test('low remaining quota defers new reads until the UTC reset while allowing fresh cache hits', async () => {
  const f = fixture(skus => reply(skus.map(sku => row(sku)),200,{'x-rate-limit-limit':'60','x-rate-limit-remaining':'10','x-rate-limit-reset':'2026-11-14T12:01:00.000'}));
  const read = createSupplierInventoryReader(f.options); await read([sku]);
  assert.equal((await read([sku])).items.length,1);
  await assert.rejects(read(['NEW']), error => error.message==='SUPPLIER_RATE_LIMITED' && error.retryAfterSeconds===61);
  assert.equal(f.calls.length,1); f.advance(61000); await read(['NEW']); assert.equal(f.calls.length,2);
});
test('supplier 429 and 503 each defer once with Retry-After; handler never retries them', async () => {
  for (const status of [429,503]) {
    const f = fixture(() => reply({private:'detail'},status,{'Retry-After':'120'}));
    const handler = createSupplierInventoryHandler(f.options), res=result(); await handler({query:{skus:sku}},res);
    assert.equal(res.statusCode,429); assert.deepEqual(res.body,{error:'SUPPLIER_RATE_LIMITED'}); assert.equal(res.headers['Retry-After'],'120');
    await handler({query:{skus:'NEW'}},result()); assert.equal(f.calls.length,1);
  }
});
test('pacing keeps inventory at forty or fewer starts in any rolling minute without headers', async () => {
  const f=fixture(),read=createSupplierInventoryReader(f.options);
  for(let i=0;i<81;i++)await read(['B'+i]);
  for(const call of f.calls)assert.ok(f.calls.filter(other=>other.at>=call.at&&other.at<call.at+60000).length<=40);
  assert.ok(f.waits.every(ms=>ms>=1500));
});
test('invalid requests, missing credentials and upstream errors never become stock zero', async () => {
  const f=fixture(),handler=createSupplierInventoryHandler(f.options);
  for(const query of [{},{skus:sku+','+sku},{skus:sku,extra:'1'}]){const res=result();await handler({query},res);assert.equal(res.statusCode,400);}
  const missing=result();await createSupplierInventoryHandler({fetchImpl:f.options.fetchImpl})({query:{skus:sku}},missing);assert.equal(missing.statusCode,503);assert.equal(f.calls.length,0);
  for(const [payload,status,code] of [[{private:'detail'},404,'UPSTREAM_HTTP_404'],[[{sku,warehouses:[]}],200,'INVALID_SUPPLIER_RESPONSE']]){
    const failed=result();await createSupplierInventoryHandler({...f.options,fetchImpl:async()=>reply(payload,status)})({query:{skus:sku}},failed);
    assert.equal(failed.statusCode,502);assert.deepEqual(failed.body,{error:code});
  }
});


test('account cost survives the same cached read; unusable prices never invalidate stock', async () => {
  const f = fixture(skus => reply(skus.map(sku => ({...row(sku), customerPrice: '2.3400'}))));
  const read = createSupplierInventoryReader(f.options), first = await read([sku]);
  f.advance(1000);
  const cached = await read([sku]);
  assert.equal(first.items[0].customerPrice, '2.34');
  assert.deepEqual(cached, first); assert.equal(f.calls.length, 1);
  for (const price of [undefined, null, '', 0, -1, 'garbage', '2.345']) {
    const [item] = normalizeProducts([{...row(sku), customerPrice: price}], [sku]);
    assert.equal(item.customerPrice, null); assert.equal(item.warehouses[0].qty, 8);
  }
});
