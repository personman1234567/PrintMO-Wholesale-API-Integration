'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { normalizeSsOrderResponse } = require('../supplier-response');
const { submitSsOrder } = require('../supplier-order-submit');
const aggregate = { B10259214: 2 };
const response = line => normalizeSsOrderResponse({ Orders: [{ OrderNumber: 'SYNTHETIC-ORDER', Lines: [line] }] }, aggregate);
test('official response sku wins over skuID regardless of JSON property order', () => {
  for (const line of [{ skuID: 3362607, sku: 'B10259214', qtyOrdered: 2 }, { sku: 'B10259214', qtyOrdered: 2, skuID: 3362607 }]) {
    const result = response(line);
    assert.equal(result.outcome, 'confirmed');
    assert.deepEqual(result.acceptedLines, [{ sku: 'B10259214', acceptedQty: 2 }]);
    assert.equal(result.acceptanceEvidence, 'supplier_reported');
  }
});
test('identifier-only evidence is retained without inventing an alias', () => {
  const result = response({ skuID: 3362607, qtyOrdered: 2 });
  assert.deepEqual(result.acceptedLines, [{ sku: '3362607', acceptedQty: 2 }]);
});
test('missing, null and empty quantity differ from explicit zero', () => {
  for (const qtyOrdered of [undefined, null, '']) {
    const result = response({ sku: 'B10259214', qtyOrdered });
    assert.equal(result.outcome, 'confirmed');
    assert.equal(result.Orders[0].Lines[0].QtyOrdered, undefined);
    assert.equal(result.acceptedLines[0].acceptedQty, undefined);
  }
  assert.equal(response({ sku: 'B10259214', qtyOrdered: 0 }).acceptedLines[0].acceptedQty, 0);
});
test('orders and native line errors coexist with original reason and code', () => {
  const result = normalizeSsOrderResponse({ Orders: [{ OrderNumber: 'SYNTHETIC-PARTIAL', Lines: [{ skuID: 1, sku: 'B10259214', qtyOrdered: 2 }] }],
    LineErrors: [{ skuID: 9, sku: 'BAD-SKU', code: 'NoInventory', message: 'Native supplier reason', requestedQty: 1 }] }, { ...aggregate, 'BAD-SKU': 1 });
  assert.equal(result.outcome, 'partial');
  assert.equal(result.Orders[0].OrderNumber, 'SYNTHETIC-PARTIAL');
  assert.equal(result.LineErrors[0].Identifier, 'BAD-SKU');
  assert.equal(result.LineErrors[0].Code, 'NoInventory');
  assert.equal(result.LineErrors[0].Message, 'Native supplier reason');
});
test('summary-derived acceptance stays labeled separately from native quantity readback', () => {
  const result = normalizeSsOrderResponse({ Orders: [{ OrderNumber: 'SYNTHETIC-SUMMARY' }] }, aggregate);
  assert.equal(result.outcome, 'confirmed');
  assert.equal(result.acceptanceEvidence, 'summary_confirmed');
});

const supplierOptions = { aggregate, orderCount: 1, purchaseOrder: 'SYNTHETIC-ERROR', testOrder: true };
const supplierEnv = { SS_ACCOUNT_NUMBER: 'fixture-account', SS_API_KEY: 'fixture-key',
  SS_PAYMENT_PROFILE_ID: '123', SS_PAYMENT_PROFILE_EMAIL: 'fixture@example.test' };

test('native JSON 503 stays separate from gateway 502 and preserves only bounded safe error evidence', async () => {
  let syntheticPosts = 0;
  await assert.rejects(submitSsOrder(supplierOptions, { env: supplierEnv, fetchImpl: async (url, options) => {
    syntheticPosts++;
    assert.equal(url, 'https://api.ssactivewear.com/v2/orders/');
    const submitted = JSON.parse(options.body);
    assert.equal(submitted.testOrder, true); assert.equal(submitted.rejectLineErrors, false);
    return new Response(JSON.stringify({ Message: 'S&S maintenance in progress', Code: 'Maintenance',
      shippingAddress: 'do-not-store-customer', PaymentProfile: 'do-not-store-payment', Authorization: 'do-not-store-auth' }),
      { status: 503, headers: { 'Content-Type': 'application/json', 'X-Private': 'do-not-store-header' } });
  } }), error => {
    assert.equal(error.status, 502); assert.equal(error.body.upstreamHttpStatus, 503);
    assert.equal(error.message, 'S&S maintenance in progress');
    assert.equal(error.body.error.message, error.message); assert.equal(error.body.error.code, 'Maintenance');
    assert.equal(error.body.responseBodyFormat, 'json'); assert.equal(error.orderSubmissionAttempted, true);
    assert.doesNotMatch(JSON.stringify(error.body), /do-not-store/);
    return true;
  });
  assert.equal(syntheticPosts, 1, 'network-free fixture invokes the order transport once, without retries');
});

test('non-JSON 503 uses an explicit safe fallback and never retains the raw body', async () => {
  await assert.rejects(submitSsOrder(supplierOptions, { env: supplierEnv, fetchImpl: async () =>
    new Response('<html>private-customer private-payment private-auth</html>', { status: 503 }) }), error => {
    assert.equal(error.status, 502); assert.equal(error.body.upstreamHttpStatus, 503);
    assert.equal(error.body.responseBodyFormat, 'non_json'); assert.equal(error.orderSubmissionAttempted, true);
    assert.match(error.body.error.message, /HTTP 503 without a readable supplier message/);
    assert.doesNotMatch(JSON.stringify(error.body), /private-|<html>/);
    return true;
  });
});

test('missing order confirmation retains actual upstream 200 rather than fabricating supplier 502', async () => {
  await assert.rejects(submitSsOrder(supplierOptions, { env: supplierEnv, fetchImpl: async () =>
    Response.json({ Message: 'No order reference was returned' }) }), error => {
    assert.equal(error.status, 502); assert.equal(error.body.upstreamHttpStatus, 200);
    assert.equal(error.body.error.message, 'No order reference was returned');
    assert.equal(error.orderSubmissionAttempted, true); return true;
  });
});
