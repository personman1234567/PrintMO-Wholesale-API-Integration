'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { normalizeSsOrderResponse } = require('../supplier-response');
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
