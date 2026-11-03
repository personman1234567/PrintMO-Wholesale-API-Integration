'use strict';

const { normalizeSsOrderResponse, supplierError } = require('./supplier-response');
const { estimateSupplierPricing } = require('./supplier-pricing');

function responseRetryEvidence(response, receivedAt) {
  const read = name => {
    const raw = response.headers?.get?.(name);
    return typeof raw === 'string' && raw.length <= 128 ? raw.trim() : '';
  };
  const retry = read('Retry-After'), remaining = read('X-Rate-Limit-Remaining');
  let retryAfterSeconds;
  if (/^\d{1,10}$/.test(retry)) retryAfterSeconds = Number(retry);
  else if (/^(Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d{2} [A-Z][a-z]{2} \d{4} \d{2}:\d{2}:\d{2} GMT$/.test(retry)) {
    const timestamp = Date.parse(retry);
    if (Number.isFinite(timestamp)) retryAfterSeconds = Math.max(0, Math.ceil((timestamp - receivedAt) / 1000));
  }
  const rateLimitRemaining = /^\d{1,15}$/.test(remaining) ? Number(remaining) : NaN;
  return {
    ...(Number.isSafeInteger(retryAfterSeconds) && retryAfterSeconds >= 0 ? { retryAfterSeconds } : {}),
    ...(Number.isSafeInteger(rateLimitRemaining) && rateLimitRemaining >= 0 ? { rateLimitRemaining } : {}),
  };
}

async function submitSsOrder(options, dependencies = {}) {
  let orderSubmissionAttempted = false;
  try {
    return await submitSsOrderRequest(options, dependencies, () => { orderSubmissionAttempted = true; });
  } catch (error) {
    if (error && typeof error === 'object') error.orderSubmissionAttempted = orderSubmissionAttempted;
    throw error;
  }
}

async function submitSsOrderRequest({ aggregate, orderCount, purchaseOrder, testOrder = true },
  { fetchImpl = fetch, env = process.env, wait, now = Date.now } = {}, markOrderSubmissionAttempted) {
  const skus = Object.keys(aggregate || {});
  if (!skus.length) throw Object.assign(new Error('No SKUs found to submit'), { status: 400 });

  const {
    SS_ACCOUNT_NUMBER,
    SS_API_KEY,
    SS_PAYMENT_PROFILE_ID,
    SS_PAYMENT_PROFILE_EMAIL,
  } = env;
  if (!SS_ACCOUNT_NUMBER || !SS_API_KEY) {
    throw Object.assign(new Error('Missing SS_ACCOUNT_NUMBER or SS_API_KEY on server'), { status: 500 });
  }
  if (!SS_PAYMENT_PROFILE_ID || !SS_PAYMENT_PROFILE_EMAIL) {
    throw Object.assign(new Error('Missing SS_PAYMENT_PROFILE_ID or SS_PAYMENT_PROFILE_EMAIL on server'), { status: 500 });
  }

  const auth = 'Basic ' + Buffer.from(`${SS_ACCOUNT_NUMBER}:${SS_API_KEY}`).toString('base64');
  // The test-order cart workflow only needs S&S to validate the lines. Reading
  // every product price first can exhaust S&S's shared API request budget for
  // a large batch before the single order POST is made.
  const { subtotal, priceWarnings } = testOrder
    ? { subtotal: null, priceWarnings: [] }
    : await estimateSupplierPricing(aggregate, { fetchImpl, authorization: auth, wait });

  const payload = {
    customer: `${purchaseOrder || 'PrintMO'} · ${orderCount} order${orderCount === 1 ? '' : 's'}`,
    testOrder: Boolean(testOrder),
    autoSelectWarehouse: true,
    rejectLineErrors: false,
    shippingAddress: {
      Name: 'LoGo Fishin Attn: TJ Reid',
      Address: '328 Bristlecone Ct S',
      City: 'Saint Charles',
      State: 'MO',
      Zip: '63304',
      Country: 'USA',
    },
    Lines: Object.entries(aggregate).map(([Identifier, Qty]) => ({ Identifier, Qty })),
    PaymentProfile: {
      ProfileID: parseInt(SS_PAYMENT_PROFILE_ID, 10),
      Email: SS_PAYMENT_PROFILE_EMAIL,
    },
  };

  markOrderSubmissionAttempted();
  const response = await fetchImpl('https://api.ssactivewear.com/v2/orders/', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: auth,
      Accept: 'application/json',
    },
    body: JSON.stringify(payload),
  });
  const responseReceivedAt = now();
  let responseBodyFormat = 'json';
  const json = await response.json().catch(() => { responseBodyFormat = 'non_json'; return {}; });
  const responseEvidence = { upstreamHttpStatus: response.status, responseBodyFormat,
    upstreamResponseAt: new Date(responseReceivedAt).toISOString(), ...responseRetryEvidence(response, responseReceivedAt) };
  if (!response.ok) throw supplierError(response.status, json,
    `S&S returned HTTP ${response.status}${responseBodyFormat === 'non_json' ? ' without a readable supplier message' : ''}.`, responseEvidence);
  const safeResponse = normalizeSsOrderResponse(json, aggregate);
  const created = safeResponse.Orders.find(order => order.OrderNumber);
  if (!created?.OrderNumber && safeResponse.outcome === 'unknown') {
    throw supplierError(502, json, 'S&S did not confirm whether an order was created.', responseEvidence);
  }
  return {
    ...safeResponse,
    orderNumber: created?.OrderNumber || null,
    count: orderCount,
    subtotal,
    skuCount: skus.length,
    priceWarnings,
    testOrder: Boolean(testOrder),
  };
}

module.exports = { submitSsOrder };
