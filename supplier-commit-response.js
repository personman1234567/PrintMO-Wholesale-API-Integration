'use strict';
const { randomUUID } = require('node:crypto');

// Observe the actual send boundary without logging supplier/customer payloads.
function sendSupplierCommitResponse(req, res, status, body, log = console.info) {
  const serialized = JSON.stringify(body);
  const responseId = `ssr-${randomUUID()}`;
  const batchId = typeof req.body?.batchId === 'string' && /^[A-Za-z0-9._:-]{1,80}$/.test(req.body.batchId)
    ? req.body.batchId : null;
  const evidence = { responseId, batchId, status, contentType: 'application/json',
    bodyBytes: Buffer.byteLength(serialized, 'utf8') };
  const emit = event => {
    try { log('S&S commit response', { ...evidence, event }); } catch { /* Diagnostics must not prevent delivery. */ }
  };
  res.setHeader('X-Order-Manager-Response-Id', responseId);
  res.setHeader('Cache-Control', 'no-store');
  if (Number.isSafeInteger(body.retryAfterSeconds) && body.retryAfterSeconds >= 0)
    res.setHeader('Retry-After', String(body.retryAfterSeconds));
  res.once('finish', () => emit('finished'));
  res.once('close', () => { if (!res.writableFinished) emit('closed_early'); });
  emit('serialized');
  return res.status(status).type('application/json').send(serialized);
}

module.exports = { sendSupplierCommitResponse };
