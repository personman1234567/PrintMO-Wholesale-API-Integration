'use strict';

function value(object, names) {
  if (!object || typeof object !== 'object') return undefined;
  const keys = Object.keys(object);
  // Name priority is contractual: sku and skuID are different identifiers.
  for (const name of names) {
    const key = keys.find(candidate => candidate.toLowerCase() === String(name).toLowerCase());
    if (key !== undefined && object[key] !== undefined && object[key] !== null) return object[key];
  }
  return undefined;
}

function text(input, fallback = '') {
  if (input === undefined || input === null) return fallback;
  if (typeof input === 'object') return fallback;
  return String(input).trim().slice(0, 500) || fallback;
}

function finiteNumber(input) {
  if (input === undefined || input === null || (typeof input === 'string' && !input.trim())) return null;
  const parsed = Number(input);
  return Number.isFinite(parsed) ? parsed : null;
}

function records(object, names) {
  const found = value(object, names);
  return Array.isArray(found) ? found : [];
}

function supplierMessage(payload, fallback) {
  const source = payload && typeof payload === 'object' ? payload : {};
  const direct = value(source, ['Message', 'Reason', 'Description', 'Detail']);
  if (direct !== undefined) return text(direct, fallback);
  const nestedError = value(source, ['error']);
  if (typeof nestedError === 'string') return text(nestedError, fallback);
  if (nestedError && typeof nestedError === 'object') {
    return text(value(nestedError, ['Message', 'Reason', 'Description', 'Detail']), fallback);
  }
  const firstError = records(source, ['errors', 'LineErrors'])[0];
  return text(value(firstError, ['Message', 'Reason', 'Description', 'Detail']), fallback);
}

function safeAcceptedLine(line) {
  const sku = text(value(line, ['Sku', 'Identifier', 'skuId', 'productSku']));
  const quantity = finiteNumber(value(line, ['AcceptedQty', 'QtyOrdered', 'Quantity', 'Qty']));
  if (!sku) return null;
  return {
    Sku: sku,
    ...(quantity !== null ? { QtyOrdered: quantity } : {}),
  };
}

function safeLineError(line, index) {
  const sku = text(value(line, ['Sku', 'Identifier', 'skuId', 'productSku']));
  const field = text(value(line, ['Field', 'Path']));
  const code = text(value(line, ['Code', 'ErrorCode', 'Type']));
  const message = text(value(line, ['Message', 'Reason', 'Error', 'Description', 'Detail']), 'S&S rejected this line.');
  const requestedQty = finiteNumber(value(line, ['RequestedQty', 'Qty', 'Quantity']));
  const availableQty = finiteNumber(value(line, ['AvailableQty', 'Available', 'InventoryQty']));
  return {
    ...(sku ? { Identifier: sku } : {}),
    ...(field ? { Field: field } : {}),
    ...(code ? { Code: code } : {}),
    Message: message,
    ...(requestedQty !== null ? { RequestedQty: requestedQty } : {}),
    ...(availableQty !== null ? { AvailableQty: availableQty } : {}),
    Line: index + 1,
  };
}

function safeValidationError(error, index) {
  const field = text(value(error, ['Field', 'Path']));
  const code = text(value(error, ['Code', 'ErrorCode', 'Type']));
  const message = text(value(error, ['Message', 'Reason', 'Error', 'Description', 'Detail']), 'S&S rejected the request.');
  return {
    ...(field ? { field } : {}),
    ...(code ? { code } : {}),
    message,
    index,
  };
}

function normalizeSsOrderResponse(payload, aggregate = {}) {
  const source = payload && typeof payload === 'object' ? payload : {};
  const rawOrders = records(source, ['Orders', 'OrderResults']);
  const Orders = rawOrders.map(order => {
    const OrderNumber = text(value(order, ['OrderNumber', 'SupplierOrderNumber']));
    const Lines = records(order, ['Lines', 'LineItems']).map(safeAcceptedLine).filter(Boolean);
    return {
      ...(OrderNumber ? { OrderNumber } : {}),
      ...(Lines.length ? { Lines } : {}),
    };
  }).filter(order => order.OrderNumber || order.Lines);
  const rawLineErrors = records(source, ['LineErrors', 'RejectedLines']);
  const rawValidationErrors = records(source, ['errors']);
  const LineErrors = (rawLineErrors.length ? rawLineErrors : rawValidationErrors)
    .map(safeLineError);
  const errors = rawValidationErrors.map(safeValidationError);

  const rejectedSkus = new Set(LineErrors.map(error => error.Identifier).filter(Boolean));
  const acceptedFromOrders = Orders.flatMap(order => order.Lines || []);
  const acceptedLines = acceptedFromOrders.length
    ? acceptedFromOrders.map(line => ({ sku: line.Sku, acceptedQty: line.QtyOrdered }))
    : Orders.some(order => order.OrderNumber) && rejectedSkus.size === LineErrors.length
      ? Object.entries(aggregate)
        .filter(([sku]) => !rejectedSkus.has(sku))
        .map(([sku, qty]) => ({ sku, acceptedQty: Number(qty) }))
      : [];

  const outcome = Orders.some(order => order.OrderNumber)
    ? LineErrors.length || errors.length ? 'partial' : 'confirmed'
    : LineErrors.length || errors.length ? 'rejected' : 'unknown';

  return {
    outcome,
    Orders,
    LineErrors,
    acceptedLines,
    acceptanceEvidence: acceptedFromOrders.length ? 'supplier_reported' : acceptedLines.length ? 'summary_confirmed' : 'unconfirmed',
    ...(errors.length ? { errors } : {}),
  };
}

function supplierError(status, payload, fallbackMessage, responseEvidence = {}) {
  const normalized = normalizeSsOrderResponse(payload);
  const message = supplierMessage(payload, fallbackMessage);
  const source = payload && typeof payload === 'object' ? payload : {};
  const nested = value(source, ['error']);
  const code = text(value(source, ['Code', 'ErrorCode', 'Type'])
    ?? value(nested, ['Code', 'ErrorCode', 'Type'])).slice(0, 80);
  const upstreamHttpStatus = Number(responseEvidence.upstreamHttpStatus ?? status);
  const orderEvidence = ['Orders', 'OrderResults'].some(name => records(source, [name]).length > 0)
    || ['OrderNumber', 'SupplierOrderNumber'].some(name => Boolean(text(value(source, [name]))))
    || ['orderNumbers', 'supplierOrderNumbers'].some(name => records(source, [name]).some(number => Boolean(text(number))))
    || ['acceptedLines', 'accepted_lines', 'Lines', 'lineItems'].some(name => records(source, [name])
      .some(line => ['AcceptedQty', 'QtyOrdered', 'Quantity', 'Qty'].some(field => Number(value(line, [field])) > 0)));
  // This exact native response is an intentional throttle inference, not a non-creation guarantee.
  const rateLimited = upstreamHttpStatus === 503 && responseEvidence.responseBodyFormat === 'json'
    && code === '503' && message.replace(/\s+/g, ' ').trim() === 'You are being throttled. Please wait 1 minute before your next request.'
    && !orderEvidence;
  const responseTime = Date.parse(responseEvidence.upstreamResponseAt);
  const headerDelay = responseEvidence.retryAfterSeconds;
  const retryAfterSeconds = rateLimited ? Math.max(60, Number.isSafeInteger(headerDelay) && headerDelay >= 0 ? headerDelay : 0)
    : Number.isSafeInteger(headerDelay) && headerDelay >= 0 ? headerDelay : null;
  const retryTime = Number.isFinite(responseTime) && retryAfterSeconds !== null ? responseTime + retryAfterSeconds * 1000 : NaN;
  const error = new Error(message);
  // Preserve an actual supplier error status; 502 describes a gateway failure,
  // not every native error (notably the documented native 503 throttle).
  error.status = Number.isInteger(Number(status)) && Number(status) >= 400 && Number(status) <= 599
    ? Number(status) : 502;
  error.body = {
    ...normalized,
    ...(upstreamHttpStatus === 503 ? { outcome: rateLimited ? 'rejected' : 'unknown' } : {}),
    ...(rateLimited ? { failureKind: 'rate_limited' } : {}),
    ...(code ? { supplierErrorCode: code } : {}),
    ...(Number.isInteger(upstreamHttpStatus) && upstreamHttpStatus >= 100 && upstreamHttpStatus <= 599
      ? { upstreamHttpStatus } : {}),
    ...(['json', 'non_json'].includes(responseEvidence.responseBodyFormat)
      ? { responseBodyFormat: responseEvidence.responseBodyFormat } : {}),
    ...(Number.isFinite(responseTime) ? { upstreamResponseAt: new Date(responseTime).toISOString() } : {}),
    ...(Number.isFinite(retryTime) && Math.abs(retryTime) <= 8640000000000000
      ? { retryAfterSeconds, retryAt: new Date(retryTime).toISOString() } : {}),
    ...(Number.isSafeInteger(responseEvidence.rateLimitRemaining) && responseEvidence.rateLimitRemaining >= 0
      ? { rateLimitRemaining: responseEvidence.rateLimitRemaining } : {}),
    error: { ...(code ? { code } : {}), message },
  };
  return error;
}

module.exports = { normalizeSsOrderResponse, supplierError, supplierMessage };
