'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createSupplierCommitFixture, fixtureGatewayKey } = require('./fixtures/supplier-commit-app');

const receivedAt = Date.parse('2026-11-03T00:00:00.000Z');
const throttleMessage = 'You are being throttled. Please wait 1 minute before your next request.';
const requestBody = { batchId: 'synthetic-throttle', poNumber: 'SYNTHETIC', testOrder: true,
  lines: [{ sku: 'B10259214', qty: 2 }], orderCount: 1 };
async function withCommit(nativeFetch, run) {
  const app = createSupplierCommitFixture({ nativeFetch, now: () => receivedAt });
  const server = await new Promise(resolve => { const started = app.listen(0, '127.0.0.1', () => resolve(started)); });
  try {
    const commit = async () => {
      const response = await fetch(`http://127.0.0.1:${server.address().port}/order-manager/v1/supplier/ss/commit`, {
        method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Order-Manager-Key': fixtureGatewayKey },
        body: JSON.stringify(requestBody),
      });
      return { status: response.status, body: await response.json() };
    };
    return await run(commit);
  } finally { await new Promise(resolve => server.close(resolve)); }
}

test('actual Express commit serializes the exact native throttle and timestamp-anchored cooldown', async () => {
  let nativeCalls = 0;
  await withCommit(async (url, options) => {
    nativeCalls++; assert.equal(url, 'https://api.ssactivewear.com/v2/orders/');
    assert.equal(JSON.parse(options.body).testOrder, true);
    return Response.json({ code: 503, message: throttleMessage, privatePayment: 'never-return-this' }, {
      status: 503, headers: { 'Retry-After': '120', 'X-Rate-Limit-Remaining': '0', 'X-Private': 'never-return-this' },
    });
  }, async commit => {
    const { status, body } = await commit();
    assert.equal(status, 502); assert.equal(body.upstreamHttpStatus, 503);
    assert.equal(body.failureKind, 'rate_limited'); assert.equal(body.outcome, 'rejected');
    assert.equal(body.supplierErrorCode, '503'); assert.equal(body.error.code, '503');
    assert.equal(body.error.message, throttleMessage); assert.equal(body.orderSubmissionAttempted, true);
    assert.equal(body.upstreamResponseAt, '2026-11-03T00:00:00.000Z');
    assert.equal(body.retryAfterSeconds, 120); assert.equal(body.retryAt, '2026-11-03T00:02:00.000Z');
    assert.equal(body.rateLimitRemaining, 0); assert.equal(body.preflightFailed, undefined);
    assert.doesNotMatch(JSON.stringify(body), /never-return-this|nothing (?:was )?(?:sent|placed)|no order/i);
  });
  assert.equal(nativeCalls, 1, 'there is no automatic supplier POST retry');
});

test('generic, incomplete, HTML and contradictory native 503 responses stay unknown through Express', async () => {
  const cases = [
    { code: 503, message: 'Service unavailable' },
    { message: throttleMessage },
    { code: 502, message: throttleMessage },
    { code: 503, message: throttleMessage + ' Extra text.' },
    { code: 503, message: throttleMessage, Orders: [{ OrderNumber: 'SYNTHETIC-ORDER' }] },
    { code: 503, message: throttleMessage, orderNumber: 'SYNTHETIC-ORDER' },
    { code: 503, message: throttleMessage, acceptedLines: [{ sku: 'B10259214', acceptedQty: 1 }] },
    { code: 503, message: throttleMessage, Orders: [], OrderResults: [{ OrderNumber: 'SYNTHETIC-ORDER' }] },
    { code: 503, message: throttleMessage, acceptedLines: [], Lines: [{ sku: 'B10259214', AcceptedQty: 0, QtyOrdered: 1 }] },
    '<html>private-payment private-customer</html>',
  ];
  let current, nativeCalls = 0;
  await withCommit(async () => {
    nativeCalls++;
    return typeof current === 'string' ? new Response(current, { status: 503 }) : Response.json(current, { status: 503 });
  }, async commit => {
    for (current of cases) {
      const { status, body } = await commit();
      assert.equal(status, 502); assert.equal(body.outcome, 'unknown');
      assert.equal(body.failureKind, undefined); assert.equal(body.orderSubmissionAttempted, true);
      assert.doesNotMatch(JSON.stringify(body), /private-payment|private-customer/);
    }
  });
  assert.equal(nativeCalls, cases.length);
});

test('exact throttle normalizes whitespace only and uses at least sixty seconds with safe headers', async () => {
  let headers = { 'Retry-After': '0', 'X-Rate-Limit-Remaining': 'invalid' };
  await withCommit(async () => Response.json({ code: '503', message: '  You are being throttled.\n Please wait 1 minute before your next request.  ' }, { status: 503, headers }), async commit => {
    let body = (await commit()).body;
    assert.equal(body.failureKind, 'rate_limited'); assert.equal(body.retryAfterSeconds, 60);
    assert.equal(body.retryAt, '2026-11-03T00:01:00.000Z'); assert.equal(body.rateLimitRemaining, undefined);
    headers = { 'Retry-After': 'Tue, 03 Nov 2026 00:03:00 GMT', 'X-Rate-Limit-Remaining': '7' };
    body = (await commit()).body;
    assert.equal(body.retryAfterSeconds, 180); assert.equal(body.retryAt, '2026-11-03T00:03:00.000Z');
    assert.equal(body.rateLimitRemaining, 7);
    headers = { 'Retry-After': 'not-a-duration', 'X-Rate-Limit-Remaining': '-1' };
    body = (await commit()).body;
    assert.equal(body.retryAfterSeconds, 60); assert.equal(body.rateLimitRemaining, undefined);
  });
});
