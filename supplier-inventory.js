const MAX_SKUS = 25;
const SKU_PATTERN = /^[A-Za-z0-9_-]{1,64}$/;
const WAREHOUSE_PATTERN = /^[A-Z0-9]{1,8}$/;

function parseSkus(value) {
  if (typeof value !== 'string') return null;
  const skus = value.split(',');
  if (!skus.length || skus.length > MAX_SKUS || skus.some(sku => !SKU_PATTERN.test(sku)) || new Set(skus).size !== skus.length) return null;
  return skus;
}

function normalizeInventory(payload, products, skus) {
  if (!Array.isArray(payload) || payload.length > skus.length) throw new Error('INVALID_SUPPLIER_RESPONSE');
  if (!Array.isArray(products) || products.length > skus.length) throw new Error('INVALID_SUPPLIER_RESPONSE');
  const requested = new Set(skus);
  const productFlags = new Map();
  for (const product of products) {
    if (!product || !requested.has(product.sku) || productFlags.has(product.sku)
      || !Array.isArray(product.warehouses) || !product.warehouses.length || product.warehouses.length > 100) {
      throw new Error('INVALID_SUPPLIER_RESPONSE');
    }
    const flags = new Map();
    for (const warehouse of product.warehouses) {
      if (!warehouse || !WAREHOUSE_PATTERN.test(warehouse.warehouseAbbr)
        || flags.has(warehouse.warehouseAbbr) || typeof warehouse.dropship !== 'boolean') {
        throw new Error('INVALID_SUPPLIER_RESPONSE');
      }
      flags.set(warehouse.warehouseAbbr, warehouse.dropship);
    }
    productFlags.set(product.sku, flags);
  }
  const seen = new Set();
  return payload.map(item => {
    if (!item || !requested.has(item.sku) || seen.has(item.sku) || !Array.isArray(item.warehouses)
      || !item.warehouses.length || item.warehouses.length > 100 || !productFlags.has(item.sku)) throw new Error('INVALID_SUPPLIER_RESPONSE');
    seen.add(item.sku);
    const warehouses = new Set();
    return {
      sku: item.sku,
      warehouses: item.warehouses.map(warehouse => {
        if (!warehouse || !WAREHOUSE_PATTERN.test(warehouse.warehouseAbbr)
          || warehouses.has(warehouse.warehouseAbbr)
          || !Number.isSafeInteger(warehouse.qty) || warehouse.qty < 0
          || !productFlags.get(item.sku).has(warehouse.warehouseAbbr)) throw new Error('INVALID_SUPPLIER_RESPONSE');
        warehouses.add(warehouse.warehouseAbbr);
        return { warehouseAbbr: warehouse.warehouseAbbr, qty: warehouse.qty,
          dropship: productFlags.get(item.sku).get(warehouse.warehouseAbbr) };
      }),
    };
  });
}

async function getSupplierJson(fetchImpl, url, auth, sleep) {
  for (let attempt = 0; attempt < 2; attempt++) {
    let response;
    try {
      response = await fetchImpl(url, {
        method: 'GET',
        headers: { Accept: 'application/json', Authorization: `Basic ${auth}` },
        redirect: 'error',
        signal: AbortSignal.timeout(15000),
      });
    } catch {
      throw new Error('UPSTREAM_TRANSPORT_FAILED');
    }
    if ((response.status === 429 || response.status >= 500) && attempt === 0) {
      const retryAfter = response.headers.get('Retry-After');
      const seconds = retryAfter === null ? 0.5 : /^\d+$/.test(retryAfter)
        ? Number(retryAfter) : (Date.parse(retryAfter) - Date.now()) / 1000;
      if (!Number.isFinite(seconds) || seconds > 2) throw new Error('UPSTREAM_RETRY_DEFERRED');
      if (typeof response.body?.cancel === 'function') await response.body.cancel();
      else if (typeof response.body?.destroy === 'function') response.body.destroy();
      await sleep(Math.max(250, seconds * 1000));
      continue;
    }
    if (!response.ok) throw new Error(`UPSTREAM_HTTP_${response.status}`);
    let payload;
    try { payload = await response.json(); }
    catch { throw new Error('UPSTREAM_INVALID_JSON'); }
    return payload;
  }
  throw new Error('UPSTREAM_RETRY_EXHAUSTED');
}

async function getSupplierInventory(fetchImpl, skus, credentials, sleep = ms => new Promise(resolve => setTimeout(resolve, ms))) {
  const suffix = skus.map(encodeURIComponent).join(',');
  const auth = Buffer.from(`${credentials.accountNumber}:${credentials.apiKey}`).toString('base64');
  const inventory = await getSupplierJson(fetchImpl, `https://api.ssactivewear.com/v2/inventory/${suffix}`, auth, sleep);
  const products = await getSupplierJson(fetchImpl, `https://api.ssactivewear.com/v2/products/${suffix}`, auth, sleep);
  return { observedAt: new Date().toISOString(), items: normalizeInventory(inventory, products, skus) };
}

function createSupplierInventoryHandler({ fetchImpl, accountNumber, apiKey, sleep } = {}) {
  return async (req, res) => {
    res.set('Cache-Control', 'no-store');
    if (Object.keys(req.query).length !== 1 || !Object.hasOwn(req.query, 'skus')) {
      return res.status(400).json({ error: 'INVALID_SKUS' });
    }
    const skus = parseSkus(req.query.skus);
    if (!skus) return res.status(400).json({ error: 'INVALID_SKUS' });
    if (!accountNumber || !apiKey) return res.status(503).json({ error: 'SUPPLIER_NOT_CONFIGURED' });
    try {
      return res.json(await getSupplierInventory(fetchImpl, skus, { accountNumber, apiKey }, sleep));
    } catch (error) {
      const code = /^UPSTREAM_[A-Z0-9_]+$|^INVALID_SUPPLIER_RESPONSE$/.test(error?.message || '')
        ? error.message : 'SUPPLIER_READ_FAILED';
      return res.status(502).json({ error: code });
    }
  };
}

module.exports = { createSupplierInventoryHandler, getSupplierInventory, normalizeInventory, parseSkus };
