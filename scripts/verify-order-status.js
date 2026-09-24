const test = require('node:test');
const assert = require('node:assert/strict');
const { normalizeOrderStatuses, parseOrderNumbers, createSupplierOrderStatusHandler } = require('../supplier-order-status');

test('split shipment stays partial until every expected box is delivered', () => {
  const order = [{ orderNumber: '32526736', orderStatus: 'Shipped', deliveryStatus: 'Shipped - Delivered', totalBoxes: 2 }];
  const rows = [[
    { orderNumber: '32526736', trackingNumber: 'TRACK1', boxNumber: 1, actualDeliveryDateTime: '2026-09-24T10:00:00' },
    { orderNumber: '32526736', trackingNumber: 'TRACK2', boxNumber: 2 },
  ]];
  const partial = normalizeOrderStatuses(order, rows, ['32526736'], '2026-09-24T12:00:00Z')[0];
  assert.equal(partial.state, 'partially_delivered');
  assert.equal(partial.deliveredBoxes, 1);
  rows[0][1].actualDeliveryDateTime = '2026-09-24T11:00:00';
  assert.equal(normalizeOrderStatuses(order, rows, ['32526736'], '2026-09-24T12:00:00Z')[0].state, 'delivered');
});

test('completed pickup and missing order do not become delivered', () => {
  const items = normalizeOrderStatuses([{ orderNumber: '32526736', orderStatus: 'Completed', totalBoxes: 0 }], [], ['32526736', '32526740'], 'now');
  assert.equal(items[0].state, 'pickup_ready');
  assert.equal(items[1].state, 'not_found');
});

test('only bounded numeric order numbers reach S&S; the gateway returns no customer data', async () => {
  assert.deepEqual(parseOrderNumbers('32526736,32526740'), ['32526736', '32526740']);
  assert.equal(parseOrderNumbers('32526736,../../secret'), null);
  const calls = [];
  const fetchImpl = async url => {
    calls.push(url);
    return { ok: true, json: async () => calls.length === 1
      ? [{ orderNumber: '32526736', orderStatus: 'Shipped', deliveryStatus: 'Shipped - Delivered', totalBoxes: 1, shippingAddress: { customer: 'Private' } }]
      : [[{ orderNumber: '32526736', trackingNumber: 'TRACK1', actualDeliveryDateTime: '2026-09-24T10:00:00' }]] };
  };
  let result;
  const res = { set() {}, status(code) { this.statusCode = code; return this; }, json(body) { result = body; return this; } };
  await createSupplierOrderStatusHandler({ fetchImpl, accountNumber: 'acct', apiKey: 'key' })({ query: { orders: '32526736' } }, res);
  assert.equal(result.items[0].state, 'delivered');
  assert(!JSON.stringify(result).includes('Private'));
  assert(calls[0].includes('/v2/orders/32526736?Boxes=true'));
  assert(calls[1].includes('/v2/TrackingDataByOrderNum/32526736?Boxes=true'));
});
