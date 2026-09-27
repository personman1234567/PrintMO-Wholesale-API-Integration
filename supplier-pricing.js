'use strict';

const { supplierError, supplierMessage } = require('./supplier-response');

const RETRYABLE_STATUSES = new Set([408, 425, 429]);

function retryableStatus(status) {
  return RETRYABLE_STATUSES.has(status) || status >= 500;
}

async function estimateSupplierPricing(aggregate, { fetchImpl, authorization, wait = (ms) => new Promise(resolve => setTimeout(resolve, ms)) }) {
  let subtotal = 0;
  const priceWarnings = [];
  let retriesRemaining = 3;

  for (const [lineIndex, [sku, qty]] of Object.entries(aggregate).entries()) {
    let response;
    let fetchError;
    for (;;) {
      try {
        response = await fetchImpl(`https://api.ssactivewear.com/v2/products/${encodeURIComponent(sku)}?mediatype=json`, {
          headers: { Authorization: authorization, Accept: 'application/json' },
        });
        fetchError = null;
      } catch (error) {
        response = null;
        fetchError = error;
      }
      if ((fetchError || retryableStatus(response.status)) && retriesRemaining > 0) {
        retriesRemaining -= 1;
        await wait(200);
        continue;
      }
      break;
    }

    if (fetchError || retryableStatus(response.status)) {
      priceWarnings.push({ sku, code: 'PRICE_LOOKUP_UNAVAILABLE', message: response
        ? `S&S price lookup returned HTTP ${response.status}.`
        : 'S&S price lookup could not be reached.' });
      continue;
    }

    const json = await response.json().catch(() => ({}));
    if (!response.ok) {
      const fallback = `S&S product lookup failed for ${sku} (HTTP ${response.status}).`;
      throw supplierError(response.status, {
        LineErrors: [{
          Identifier: sku,
          Field: `lines[${lineIndex}].identifier`,
          Code: 'PRODUCT_LOOKUP_FAILED',
          Message: supplierMessage(json, fallback),
          RequestedQty: qty,
        }],
      }, fallback);
    }
    const product = Array.isArray(json) ? json[0] : json;
    const raw =
      product?.customerPrice ?? product?.CustomerPrice ??
      product?.piecePrice ?? product?.PiecePrice ??
      product?.salePrice ?? product?.SalePrice ??
      product?.casePrice ?? product?.CasePrice ??
      product?.Price ?? product?.price ?? null;
    const parsed = raw == null ? NaN : parseFloat(String(raw));
    if (Number.isFinite(parsed)) subtotal += parsed * qty;
    else priceWarnings.push({ sku, code: 'PRICE_NOT_PROVIDED', message: 'S&S did not provide a usable price.' });
  }

  return {
    subtotal: priceWarnings.length ? null : Number(subtotal.toFixed(2)),
    priceWarnings,
  };
}

module.exports = { estimateSupplierPricing };
