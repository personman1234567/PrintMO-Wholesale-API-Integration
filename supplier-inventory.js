const MAX_SKUS = 250;
const CACHE_TTL_MS = 60000;
const SKU_PATTERN = /^[A-Za-z0-9_-]{1,64}$/;
const WAREHOUSE_PATTERN = /^[A-Z0-9]{1,8}$/;

function customerCost(value) {
  if (!['string', 'number'].includes(typeof value)) return null;
  const text = String(value).trim();
  if (!/^\d{1,7}(?:\.\d{1,2}0*)?$/.test(text) || Number(text) <= 0) return null;
  return Number(text).toFixed(2);
}

function parseSkus(value) {
  if (typeof value !== 'string') return null;
  const skus = value.split(',');
  if (!skus.length || skus.length > MAX_SKUS || skus.some(sku => !SKU_PATTERN.test(sku)) || new Set(skus).size !== skus.length) return null;
  return skus;
}

// Products supplies live available-for-sale quantities and dropship flags together.
// DS vendor duplicates are excluded by consumers; never merge physical rows.
function normalizeProducts(products, skus) {
  if (!Array.isArray(products) || products.length > skus.length) throw new Error('INVALID_SUPPLIER_RESPONSE');
  const requested = new Set(skus), seen = new Set();
  return products.map(product => {
    if (!product || !requested.has(product.sku) || seen.has(product.sku)
      || !Array.isArray(product.warehouses) || !product.warehouses.length || product.warehouses.length > 100) throw new Error('INVALID_SUPPLIER_RESPONSE');
    seen.add(product.sku);
    const warehouses = new Map();
    for (const warehouse of product.warehouses) {
      if (!warehouse || !WAREHOUSE_PATTERN.test(warehouse.warehouseAbbr)
        || typeof warehouse.dropship !== 'boolean' || !Number.isSafeInteger(warehouse.qty) || warehouse.qty < 0) throw new Error('INVALID_SUPPLIER_RESPONSE');
      if (warehouses.has(warehouse.warehouseAbbr)) {
        if (warehouse.warehouseAbbr === 'DS' && warehouse.dropship === true && warehouses.get('DS').dropship === true) continue;
        throw new Error('INVALID_SUPPLIER_RESPONSE');
      }
      warehouses.set(warehouse.warehouseAbbr, { warehouseAbbr: warehouse.warehouseAbbr, qty: warehouse.qty, dropship: warehouse.dropship });
    }
    return { sku: product.sku, warehouses: [...warehouses.values()],
      ...(Object.hasOwn(product, 'customerPrice') ? { customerPrice: customerCost(product.customerPrice) } : {}) };
  });
}
function resetTime(value, now) {
  if (!value) return null;
  if (/^\d+(?:\.\d+)?$/.test(value)) {
    const n = Number(value);
    return n > 1e12 ? n : n > 1e9 ? n * 1000 : now + n * 1000;
  }
  // S&S's ISO reset value lacks a suffix but denotes UTC, not host local time.
  const parsed = Date.parse(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?$/.test(value) ? value + 'Z' : value);
  return Number.isFinite(parsed) ? parsed : null;
}
function retryTime(value, now) {
  if (!value) return null;
  const parsed = /^\d+$/.test(value) ? now + Number(value) * 1000 : Date.parse(value);
  return Number.isFinite(parsed) ? parsed : null;
}
function deferred(code, retryAt, now) {
  const error = new Error(code);
  error.retryAfterSeconds = Math.max(1, Math.ceil((retryAt - now) / 1000));
  return error;
}

// Per gateway instance/account: serialize fills, coalesce overlap, reserve ten
// requests for other consumers, cap this reader at forty starts per rolling minute.
function createSupplierInventoryReader({ fetchImpl, accountNumber, apiKey, now = Date.now,
  sleep = ms => new Promise(resolve => setTimeout(resolve, ms)) } = {}) {
  const auth = Buffer.from(accountNumber + ':' + apiKey).toString('base64');
  const cache = new Map(), starts = [];
  let tail = Promise.resolve(), queued = 0, blockedUntil = 0, nextStart = 0;
  async function read(skus) {
    const current = now();
    const missing = skus.filter(sku => {
      const entry = cache.get(sku);
      return !entry || current < entry.fetchedAt || current - entry.fetchedAt >= CACHE_TTL_MS;
    });
    if (missing.length) {
      while (starts.length && starts[0] <= now() - 60000) starts.shift();
      const slot = Math.max(blockedUntil, nextStart, starts.length >= 40 ? starts[0] + 60000 : 0);
      if (slot - now() > 2000) throw deferred('SUPPLIER_RATE_LIMITED', slot, now());
      if (slot > now()) await sleep(slot - now());
      const fetchedAt = now();
      starts.push(fetchedAt); nextStart = fetchedAt + 1500;
      let response;
      try {
        response = await fetchImpl('https://api.ssactivewear.com/v2/products/' + missing.map(encodeURIComponent).join(',') + '?fields=sku,styleID,warehouses,customerPrice', {
          method: 'GET', headers: { Accept: 'application/json', Authorization: 'Basic ' + auth },
          redirect: 'error', signal: AbortSignal.timeout(15000),
        });
      } catch { throw new Error('UPSTREAM_TRANSPORT_FAILED'); }
      const remainingHeader = response.headers.get('x-rate-limit-remaining'), limitHeader = response.headers.get('x-rate-limit-limit');
      const remaining = remainingHeader !== null && /^\d+$/.test(remainingHeader) ? Number(remainingHeader) : null;
      const limit = limitHeader !== null && /^\d+$/.test(limitHeader) ? Number(limitHeader) : null;
      const reset = resetTime(response.headers.get('x-rate-limit-reset'), now()), retry = retryTime(response.headers.get('Retry-After'), now());
      if (limit > 0) nextStart = Math.max(nextStart, fetchedAt + Math.ceil(60000 / Math.max(1, Math.min(40, limit - 10))));
      if ((remaining !== null && remaining <= 10) || response.status === 429 || response.status === 503) {
        blockedUntil = Math.max(blockedUntil, reset > now() ? reset + 1000 : now() + 60000, retry || 0);
      }
      if (!response.ok) {
        if (typeof response.body?.cancel === 'function') await response.body.cancel();
        else if (typeof response.body?.destroy === 'function') response.body.destroy();
        if (response.status === 429 || response.status === 503) throw deferred('SUPPLIER_RATE_LIMITED', blockedUntil, now());
        const error = new Error('UPSTREAM_HTTP_' + response.status);
        if (response.status >= 500) error.retryAfterSeconds = Math.max(1, Math.ceil(((retry || now() + 60000) - now()) / 1000));
        throw error;
      }
      let payload;
      try { payload = await response.json(); } catch { throw new Error('UPSTREAM_INVALID_JSON'); }
      const items = normalizeProducts(payload, missing), bySku = new Map(items.map(item => [item.sku, item]));
      if (now() - fetchedAt >= CACHE_TTL_MS) throw new Error('SUPPLIER_SOURCE_STALE');
      for (const sku of missing) { cache.delete(sku); cache.set(sku, { fetchedAt, item: bySku.get(sku) || null }); }
      // Successful omissions stay omissions. Bound memory without stale fallback.
      while (cache.size > 30000) cache.delete(cache.keys().next().value);
    }
    const entries = skus.map(sku => cache.get(sku));
    if (entries.some(entry => !entry || now() < entry.fetchedAt || now() - entry.fetchedAt >= CACHE_TTL_MS)) throw new Error('SUPPLIER_SOURCE_STALE');
    return { observedAt: new Date(Math.min(...entries.map(entry => entry.fetchedAt))).toISOString(), items: entries.flatMap(entry => entry.item ? [entry.item] : []) };
  }
  return skus => {
    if (!Array.isArray(skus) || !parseSkus(skus.join(','))) return Promise.reject(new Error('INVALID_SKUS'));
    if (queued >= 8) return Promise.reject(deferred('SUPPLIER_RATE_LIMITED', now() + 2000, now()));
    queued++;
    const result = tail.then(() => read(skus)).finally(() => { queued--; });
    tail = result.catch(() => {});
    return result;
  };
}
function createSupplierInventoryHandler(options = {}) {
  const read = createSupplierInventoryReader(options);
  return async (req, res) => {
    res.set('Cache-Control', 'no-store');
    if (Object.keys(req.query).length !== 1 || !Object.hasOwn(req.query, 'skus')) return res.status(400).json({ error: 'INVALID_SKUS' });
    const skus = parseSkus(req.query.skus);
    if (!skus) return res.status(400).json({ error: 'INVALID_SKUS' });
    if (!options.accountNumber || !options.apiKey) return res.status(503).json({ error: 'SUPPLIER_NOT_CONFIGURED' });
    try { return res.json(await read(skus)); }
    catch (error) {
      const code = /^UPSTREAM_[A-Z0-9_]+$|^INVALID_SUPPLIER_RESPONSE$|^SUPPLIER_(RATE_LIMITED|SOURCE_STALE)$/.test(error?.message || '') ? error.message : 'SUPPLIER_READ_FAILED';
      if (error.retryAfterSeconds) res.set('Retry-After', String(error.retryAfterSeconds));
      return res.status(code === 'SUPPLIER_RATE_LIMITED' ? 429 : 502).json({ error: code });
    }
  };
}
module.exports = { MAX_SKUS, CACHE_TTL_MS, createSupplierInventoryHandler, createSupplierInventoryReader, normalizeProducts, parseSkus };
