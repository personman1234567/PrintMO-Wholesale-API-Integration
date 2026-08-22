'use strict';

function value(object, names) {
  if (!object || typeof object !== 'object') return undefined;
  const wanted = new Set(names.map(name => String(name).toLowerCase()));
  const key = Object.keys(object).find(candidate => wanted.has(candidate.toLowerCase()));
  return key ? object[key] : undefined;
}

function text(input, fallback = '') {
  if (input === undefined || input === null) return fallback;
  if (typeof input === 'object') return fallback;
  return String(input).trim().slice(0, 500) || fallback;
}

function finiteNumber(input) {
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
    ...(errors.length ? { errors } : {}),
  };
}

function supplierError(status, payload, fallbackMessage) {
  const normalized = normalizeSsOrderResponse(payload);
  const error = new Error(fallbackMessage);
  error.status = [400, 404, 422].includes(Number(status)) ? Number(status) : 502;
  error.body = {
    ...normalized,
    error: { message: fallbackMessage },
  };
  return error;
}

module.exports = { normalizeSsOrderResponse, supplierError, supplierMessage };
