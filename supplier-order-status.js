const ORDER_NUMBER = /^\d{5,12}$/;

function parseOrderNumbers(value) {
  if (typeof value !== 'string') return null;
  const numbers = value.split(',');
  if (!numbers.length || numbers.length > 25 || numbers.some(number => !ORDER_NUMBER.test(number))
    || new Set(numbers).size !== numbers.length) return null;
  return numbers;
}

function flattenTracking(value) {
  if (!Array.isArray(value)) throw new Error('INVALID_SUPPLIER_RESPONSE');
  return value.flatMap(group => {
    if (Array.isArray(group)) return group;
    if (group && typeof group === 'object') return [group];
    throw new Error('INVALID_SUPPLIER_RESPONSE');
  });
}

function normalizeOrderStatuses(orders, tracking, requested, observedAt) {
  if (!Array.isArray(orders)) throw new Error('INVALID_SUPPLIER_RESPONSE');
  const wanted = new Set(requested);
  const byNumber = new Map();
  for (const order of orders) {
    const number = String(order?.orderNumber || '');
    if (!wanted.has(number) || byNumber.has(number)) throw new Error('INVALID_SUPPLIER_RESPONSE');
    byNumber.set(number, order);
  }
  const tracks = new Map(requested.map(number => [number, new Map()]));
  for (const row of flattenTracking(tracking)) {
    const number = String(row?.orderNumber || '');
    const trackingNumber = String(row?.trackingNumber || '').trim().slice(0, 120);
    const boxNumber = String(row?.boxNumber || '').trim().slice(0, 40);
    if (!wanted.has(number) || !trackingNumber || !byNumber.has(number)) throw new Error('INVALID_SUPPLIER_RESPONSE');
    const key = `${trackingNumber}:${boxNumber}`;
    const boxes = tracks.get(number);
    boxes.set(key, {
      trackingNumber,
      boxNumber,
      carrier: String(row?.carrierName || '').slice(0, 80),
      deliveredAt: row?.actualDeliveryDateTime || null,
      checkpoint: String(row?.latestCheckpoint?.checkpointStatusMessage || '').slice(0, 240),
    });
  }
  return requested.map(number => {
    const order = byNumber.get(number);
    if (!order) return { orderNumber: number, state: 'not_found', observedAt };
    const boxes = [...tracks.get(number).values()];
    const totalBoxes = Math.max(0, Math.min(1000, Number(order.totalBoxes) || 0));
    const deliveredBoxes = boxes.filter(box => Boolean(box.deliveredAt)).length;
    const deliveryStatus = String(order.deliveryStatus || '').slice(0, 80);
    const orderStatus = String(order.orderStatus || '').slice(0, 80);
    let state = 'processing';
    if (orderStatus.toLowerCase() === 'canceled') state = 'canceled';
    else if (deliveryStatus.toLowerCase().includes('exception') || boxes.some(box => /exception|failed delivery|return to sender/i.test(box.checkpoint))) state = 'exception';
    else if (totalBoxes > 1 && deliveredBoxes > 0 && deliveredBoxes < totalBoxes) state = 'partially_delivered';
    else if ((totalBoxes > 0 && deliveredBoxes >= totalBoxes) || (totalBoxes <= 1
      && deliveryStatus.toLowerCase() === 'shipped - delivered'
      && (!boxes.length || deliveredBoxes === boxes.length))) state = 'delivered';
    else if (deliveryStatus.toLowerCase().includes('out for delivery')) state = 'out_for_delivery';
    else if (orderStatus.toLowerCase() === 'shipped' || deliveryStatus.toLowerCase().startsWith('shipped')) state = 'in_transit';
    else if (orderStatus.toLowerCase() === 'completed') state = 'pickup_ready';
    return {
      orderNumber: number, state, orderStatus, deliveryStatus,
      totalBoxes, deliveredBoxes, boxes,
      trackingNumber: String(order.trackingNumber || '').slice(0, 120),
      observedAt,
    };
  });
}

async function supplierGet(fetchImpl, url, auth, missingIsEmpty = false) {
  let response;
  try {
    response = await fetchImpl(url, {
      headers: { Accept: 'application/json', Authorization: `Basic ${auth}` },
      redirect: 'error', signal: AbortSignal.timeout(15000),
    });
  } catch { throw new Error('UPSTREAM_TRANSPORT_FAILED'); }
  if (missingIsEmpty && response.status === 404) return [];
  if (!response.ok) throw new Error(`UPSTREAM_HTTP_${response.status}`);
  try { return await response.json(); }
  catch { throw new Error('UPSTREAM_INVALID_JSON'); }
}

function createSupplierOrderStatusHandler({ fetchImpl, accountNumber, apiKey }) {
  return async (req, res) => {
    res.set('Cache-Control', 'no-store');
    if (Object.keys(req.query).length !== 1 || !Object.hasOwn(req.query, 'orders')) return res.status(400).json({ error: 'INVALID_ORDER_NUMBERS' });
    const numbers = parseOrderNumbers(req.query.orders);
    if (!numbers) return res.status(400).json({ error: 'INVALID_ORDER_NUMBERS' });
    if (!accountNumber || !apiKey) return res.status(503).json({ error: 'SUPPLIER_NOT_CONFIGURED' });
    try {
      const auth = Buffer.from(`${accountNumber}:${apiKey}`).toString('base64');
      const suffix = numbers.join(',');
      const orders = await supplierGet(fetchImpl, `https://api.ssactivewear.com/v2/orders/${suffix}?Boxes=true`, auth, true);
      const tracking = await supplierGet(fetchImpl, `https://api.ssactivewear.com/v2/TrackingDataByOrderNum/${suffix}?Boxes=true`, auth, true);
      const observedAt = new Date().toISOString();
      return res.json({ observedAt, items: normalizeOrderStatuses(orders, tracking, numbers, observedAt) });
    } catch (error) {
      const code = /^UPSTREAM_[A-Z0-9_]+$|^INVALID_SUPPLIER_RESPONSE$/.test(error?.message || '')
        ? error.message : 'SUPPLIER_READ_FAILED';
      return res.status(502).json({ error: code });
    }
  };
}

module.exports = { createSupplierOrderStatusHandler, normalizeOrderStatuses, parseOrderNumbers };
