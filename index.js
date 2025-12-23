require('dotenv').config();
const express = require('express');
const crypto = require('crypto');
const fetch = require('node-fetch').default; // reserved for future use
const { createClient } = require('redis');
const cors = require('cors');

const app = express();

// ─── Redis Setup ───────────────────────────────────────────────────────────────
const redis = createClient({ url: process.env.REDIS_URL });
redis.on('error', err => console.error('❌ Redis error', err));
redis
  .connect()
  .then(() => console.log('✅ Redis connected'))
  .catch(console.error);

const QUEUE_KEY = 'shopifyOrdersQueue';

// Load secrets
const {
  SHOPIFY_WEBHOOK_SECRET,
  PUBLIC_R2_BASE,
  ORDER_MANAGER_UI_ORIGIN,
  ORDER_MANAGER_ADMIN_KEY,
} = process.env;

// ─── Helpers ──────────────────────────────────────────────────────────────────
function verifyShopifyWebhook(req) {
  const hmacHeader = req.get('X-Shopify-Hmac-Sha256');
  if (!hmacHeader) return true; // allow local testing

  const computed = crypto
    .createHmac('sha256', SHOPIFY_WEBHOOK_SECRET)
    .update(req.body, 'utf8')
    .digest('base64');

  return crypto.timingSafeEqual(
    Buffer.from(computed, 'utf8'),
    Buffer.from(hmacHeader, 'utf8')
  );
}

function slug(s) {
  return String(s || '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 40);
}

function extFromBasename(name) {
  const m = String(name || '').match(/\.([A-Za-z0-9]+)$/);
  return m ? m[1].toLowerCase() : '';
}

function sideFromBasename(name) {
  const m = String(name || '').match(/_(front|back|left|right|breast|side)(?:\.[^.]+)?$/i);
  return m ? m[1].toLowerCase() : '';
}

function propertiesToMap(line) {
  const out = {};
  const arr = Array.isArray(line?.properties) ? line.properties : [];
  for (const p of arr) {
    const key = (p?.name || p?.key || '').toString();
    if (!key) continue;
    out[key] = p?.value ?? '';
    out[key.toLowerCase()] = p?.value ?? '';
  }
  return out;
}

function tryURL(u) {
  try {
    return new URL(u);
  } catch {
    return null;
  }
}

function basenameFromPath(p) {
  if (!p) return '';
  const parts = p.split('/');
  return parts[parts.length - 1] || '';
}

/**
 * Convert a preview URL to a promoted ORDERS URL.
 * previews/YYYY-MM-DD/<designRef>/<rest>  →  orders/${orderNumber}_${custSlug}/<designRef>/<rest>
 */
function promotedUrlFromPreview(previewUrl, { orderNumber, custSlug, designRef }) {
  if (!previewUrl || !orderNumber || !custSlug || !designRef) return null;
  const u = tryURL(previewUrl);
  if (!u) return null;

  const baseOrigin =
    (PUBLIC_R2_BASE && PUBLIC_R2_BASE.replace(/\/+$/, '')) || u.origin;

  // Expected: /previews/2025-11-07/<designRef>/<rest...>
  const re = /^\/previews\/\d{4}-\d{2}-\d{2}\/([^/]+)\/(.+)$/;
  const m = u.pathname.match(re);

  let rest = '';
  if (m && m[2]) {
    rest = m[2];
  } else {
    rest = basenameFromPath(u.pathname);
  }

  const key = `orders/${orderNumber}_${custSlug}/${designRef}/${rest}`;
  return { key, url: `${baseOrigin}/${key}`, rest };
}

function normalizeName(s) {
  return String(s || '')
    .normalize('NFKC')
    .replace(/[‐-‒–—―]/g, '-') // any dash variant -> hyphen
    .replace(/\s+/g, ' ') // collapse whitespace
    .trim();
}

function extractOrderNumberFromName(name) {
  const m = String(name || '').match(/#?(\d{3,})/);
  return m ? m[1] : null;
}

// ─── Order Manager API: CORS + Auth ────────────────────────────────────────────
const UI_ORIGIN = ORDER_MANAGER_UI_ORIGIN || 'https://print-mo-order-manager.pages.dev';
const ADMIN_KEY = ORDER_MANAGER_ADMIN_KEY;

function requireAdminKey(req, res, next) {
  // Let CORS preflights through (they won't include your custom header)
  if (req.method === 'OPTIONS') return next();

  const key = req.get('X-Order-Manager-Key');
  if (!ADMIN_KEY) return res.status(500).json({ error: 'Missing ORDER_MANAGER_ADMIN_KEY on server' });
  if (!key || key !== ADMIN_KEY) return res.status(401).json({ error: 'Unauthorized' });
  next();
}

const corsOptions = {
  origin(origin, cb) {
    if (!origin) return cb(null, true); // curl/server-to-server
    if (origin === UI_ORIGIN) return cb(null, true);
    // allow preview deployments if your origin varies
    if (origin.endsWith('.print-mo-order-manager.pages.dev')) return cb(null, true);
    return cb(new Error('CORS blocked: ' + origin));
  },
  methods: ['GET', 'PATCH', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'X-Order-Manager-Key'],
};

// Apply CORS for all /order-manager requests (this alone is enough to satisfy preflight)
app.use('/order-manager', cors(corsOptions));

// Parse JSON bodies ONLY for /order-manager routes (so webhook raw body stays intact)
app.use('/order-manager', express.json({ limit: '2mb' }));
app.use('/order-manager', express.urlencoded({ extended: true }));

// ─── Webhook ──────────────────────────────────────────────────────────────────
app.post('/webhooks/orders/paid', express.raw({ type: 'application/json' }), async (req, res) => {
  console.log(`\n[Webhook Triggered] orders/paid at ${new Date().toISOString()}`);
  if (!verifyShopifyWebhook(req)) return res.status(401).send('☠️ Unauthorized');

  const order = JSON.parse(req.body.toString());

  // Order context
  const orderNumber =
    String(order.order_number || order.name || order.id || '').replace('#', '') || 'order';

  const first = order?.customer?.first_name || order?.billing_address?.first_name || '';
  const last = order?.customer?.last_name || order?.billing_address?.last_name || '';
  const customerName = `${first} ${last}`.trim() || 'Guest';
  const custSlug = slug(customerName || 'customer');

  // Price fields
  const subtotal = parseFloat(order.current_subtotal_price || order.subtotal_price || 0) || 0;
  const discount = parseFloat(order.total_discounts || order.current_total_discounts || 0) || 0;
  const total = parseFloat(order.total_price || order.current_total_price || 0) || 0;

  let derivedAssets = 0;

  // Map every line_item and attach a promoted orders URL derived from preview URL
  const items = (order.line_items || []).map(li => {
    const unitPrice = parseFloat(li.price || '0') || 0;
    const qty = li.quantity || 0;
    const props = propertiesToMap(li);

    // designRef in properties (support both keys)
    const designRef = (props['_designref'] || props['_design_ref'] || '').toString().trim();
    const previewUrl = (props['design_preview_url'] || props['design-preview-url'] || '')
      .toString()
      .trim();

    let assets = [];
    if (designRef && previewUrl) {
      const built = promotedUrlFromPreview(previewUrl, { orderNumber, custSlug, designRef });
      if (built) {
        const fileName = basenameFromPath(built.url);
        const ext = extFromBasename(fileName);
        const side = sideFromBasename(fileName) || null;
        const role = li.sku ? 'mockup' : 'design';
        assets.push({ key: built.key, url: built.url, ext, side, role });
        derivedAssets++;
      }
    }

    return {
      title: li.title || li.name,
      sku: li.sku || null,
      qty,
      unitPrice,
      lineTotal: parseFloat((unitPrice * qty).toFixed(2)),
      variantId: li.variant_id,
      variantTitle: li.variant_title || '',
      designRef: designRef || null,
      assets,
      _previewUrl: previewUrl || null,
    };
  });

  // Build the enriched record
  const record = {
    name: `${order.name} – ${customerName}`,
    orderNumber,
    customerSlug: custSlug,
    receivedAt: new Date().toISOString(),
    subtotal,
    discount,
    total,
    items,
    status: 'received',
  };

  // Push to Redis
  await redis.rPush(QUEUE_KEY, JSON.stringify(record));
  console.log(`📥 Queued ${record.name} (subtotal $${subtotal.toFixed(2)}), assets derived: ${derivedAssets}`);
  res.status(200).send('Queued');
});

// ─── Order Manager Endpoints (UI-facing) ───────────────────────────────────────
const ALLOWED_STATUSES = new Set(['received', 'toOrder', 'blanks', 'print']);

function normalizeRecord(rec) {
  if (!rec.status) rec.status = 'received';
  return rec;
}

app.get('/order-manager/queue', requireAdminKey, async (req, res) => {
  const items = await redis.lRange(QUEUE_KEY, 0, -1);
  const orders = [];
  for (const s of items) {
    try {
      orders.push(normalizeRecord(JSON.parse(s)));
    } catch {}
  }
  res.json({ orders });
});

app.patch('/order-manager/orders/status', requireAdminKey, async (req, res) => {
  const { name, status } = req.body || {};

  if (typeof name !== 'string' || !name.trim()) {
    return res.status(400).json({ error: 'Missing name' });
  }
  if (typeof status !== 'string' || !ALLOWED_STATUSES.has(status)) {
    return res.status(400).json({ error: 'Bad status' });
  }

  const items = await redis.lRange(QUEUE_KEY, 0, -1);

  const reqNorm = normalizeName(name);
  const reqOrderNumber = extractOrderNumberFromName(name);

  let foundIndex = -1;
  let rec = null;

  for (let i = 0; i < items.length; i++) {
    try {
      const r = JSON.parse(items[i]);
      if (!r) continue;

      if (r.name === name) { foundIndex = i; rec = r; break; }
      if (normalizeName(r.name) === reqNorm) { foundIndex = i; rec = r; break; }
      if (reqOrderNumber && String(r.orderNumber) === String(reqOrderNumber)) {
        foundIndex = i; rec = r; break;
      }
    } catch {}
  }

  if (foundIndex === -1) {
    const sampleNames = [];
    for (let i = 0; i < Math.min(items.length, 5); i++) {
      try { sampleNames.push(JSON.parse(items[i])?.name); } catch {}
    }
    return res.status(404).json({
      error: 'Order not found',
      queueLength: items.length,
      requestedName: name,
      requestedNameNormalized: reqNorm,
      requestedOrderNumber: reqOrderNumber,
      sampleNames: sampleNames.filter(Boolean),
    });
  }

  rec.status = status;
  await redis.lSet(QUEUE_KEY, foundIndex, JSON.stringify(rec));
  res.json({ ok: true });
});

// ---- Shared helpers for order-manager mutations ----
function asInt01(v, fallback = 0) {
  if (v === true) return 1;
  if (v === false) return 0;
  const n = Number(v);
  if (Number.isFinite(n)) return n;
  return fallback;
}

function asString(v, fallback = '') {
  if (v === null || v === undefined) return fallback;
  return String(v);
}

function normalizeRecord(rec) {
  if (!rec.status) rec.status = 'received';
  if (rec.blanksStatus == null) rec.blanksStatus = 0;
  if (rec.printsStatus == null) rec.printsStatus = 0;
  if (rec.blanksOrdered == null) rec.blanksOrdered = 0;
  if (rec.printsOrdered == null) rec.printsOrdered = 0;
  if (rec.notes == null) rec.notes = '';
  if (rec.bundle == null) rec.bundle = '';
  if (!Array.isArray(rec.attachments)) rec.attachments = []; // metadata only for now
  return rec;
}

async function withOrderByName(name, mutatorFn) {
  const items = await redis.lRange(QUEUE_KEY, 0, -1);

  const reqNorm = normalizeName(name);
  const reqOrderNumber = extractOrderNumberFromName(name);

  let foundIndex = -1;
  let rec = null;

  for (let i = 0; i < items.length; i++) {
    try {
      const r = normalizeRecord(JSON.parse(items[i]));
      if (!r) continue;

      if (r.name === name) { foundIndex = i; rec = r; break; }
      if (normalizeName(r.name) === reqNorm) { foundIndex = i; rec = r; break; }
      if (reqOrderNumber && String(r.orderNumber) === String(reqOrderNumber)) { foundIndex = i; rec = r; break; }
    } catch {}
  }

  if (foundIndex === -1) {
    const sampleNames = [];
    for (let i = 0; i < Math.min(items.length, 5); i++) {
      try { sampleNames.push(JSON.parse(items[i])?.name); } catch {}
    }
    return { ok: false, status: 404, body: { error: 'Order not found', queueLength: items.length, requestedName: name, sampleNames: sampleNames.filter(Boolean) } };
  }

  // mutate + save
  mutatorFn(rec);
  normalizeRecord(rec);
  await redis.lSet(QUEUE_KEY, foundIndex, JSON.stringify(rec));
  return { ok: true, status: 200, body: { ok: true } };
}

// ---- Endpoints: Notes, Bundle, Ready/Progress, Rename, Delete ----

// Notes
app.patch('/order-manager/orders/notes', requireAdminKey, async (req, res) => {
  const { name, notes } = req.body || {};
  if (typeof name !== 'string' || !name.trim()) return res.status(400).json({ error: 'Missing name' });

  const result = await withOrderByName(name, (rec) => {
    rec.notes = asString(notes, '');
  });

  return res.status(result.status).json(result.body);
});

// Bundle (set or clear)
app.patch('/order-manager/orders/bundle', requireAdminKey, async (req, res) => {
  const { name, bundle } = req.body || {};
  if (typeof name !== 'string' || !name.trim()) return res.status(400).json({ error: 'Missing name' });

  const result = await withOrderByName(name, (rec) => {
    rec.bundle = asString(bundle, '').trim();
  });

  return res.status(result.status).json(result.body);
});

// Ready flags (the checkboxes / header state)
app.patch('/order-manager/orders/ready', requireAdminKey, async (req, res) => {
  const { name, blanksStatus, printsStatus, blanksOrdered, printsOrdered } = req.body || {};
  if (typeof name !== 'string' || !name.trim()) return res.status(400).json({ error: 'Missing name' });

  const result = await withOrderByName(name, (rec) => {
    if (blanksStatus !== undefined) rec.blanksStatus = asInt01(blanksStatus, rec.blanksStatus ?? 0);
    if (printsStatus !== undefined) rec.printsStatus = asInt01(printsStatus, rec.printsStatus ?? 0);
    if (blanksOrdered !== undefined) rec.blanksOrdered = asInt01(blanksOrdered, rec.blanksOrdered ?? 0);
    if (printsOrdered !== undefined) rec.printsOrdered = asInt01(printsOrdered, rec.printsOrdered ?? 0);
  });

  return res.status(result.status).json(result.body);
});

// Progress (generic numeric field; if your UI calls updateProgress)
app.patch('/order-manager/orders/progress', requireAdminKey, async (req, res) => {
  const { name, progress } = req.body || {};
  if (typeof name !== 'string' || !name.trim()) return res.status(400).json({ error: 'Missing name' });

  const result = await withOrderByName(name, (rec) => {
    rec.progress = asInt01(progress, rec.progress ?? 0);
  });

  return res.status(result.status).json(result.body);
});

// Rename (careful: your UI uses name as identity; only use if you really need it)
app.patch('/order-manager/orders/rename', requireAdminKey, async (req, res) => {
  const { name, newName } = req.body || {};
  if (typeof name !== 'string' || !name.trim()) return res.status(400).json({ error: 'Missing name' });
  if (typeof newName !== 'string' || !newName.trim()) return res.status(400).json({ error: 'Missing newName' });

  const result = await withOrderByName(name, (rec) => {
    rec.name = newName.trim();
  });

  return res.status(result.status).json(result.body);
});

// Delete
app.post('/order-manager/orders/delete', requireAdminKey, async (req, res) => {
  const { name } = req.body || {};
  if (typeof name !== 'string' || !name.trim()) return res.status(400).json({ error: 'Missing name' });

  const items = await redis.lRange(QUEUE_KEY, 0, -1);

  const reqNorm = normalizeName(name);
  const reqOrderNumber = extractOrderNumberFromName(name);

  let foundIndex = -1;

  for (let i = 0; i < items.length; i++) {
    try {
      const r = JSON.parse(items[i]);
      if (!r) continue;

      if (r.name === name) { foundIndex = i; break; }
      if (normalizeName(r.name) === reqNorm) { foundIndex = i; break; }
      if (reqOrderNumber && String(r.orderNumber) === String(reqOrderNumber)) { foundIndex = i; break; }
    } catch {}
  }

  if (foundIndex === -1) return res.status(404).json({ error: 'Order not found' });

  await redis.lRem(QUEUE_KEY, 1, items[foundIndex]); // remove first matching serialized entry
  return res.json({ ok: true });
});

// Submit batch to S&S (server-side)
app.post('/order-manager/orders/process-batch', requireAdminKey, async (req, res) => {
  try {
    const body = req.body || {};
    const names =
      (Array.isArray(body.names) && body.names) ||
      (Array.isArray(body.orderNames) && body.orderNames) ||
      (Array.isArray(body.orderIds) && body.orderIds) ||
      (Array.isArray(body.ids) && body.ids) ||
      [];

    if (!names.length) return res.status(400).json({ error: 'No orders to submit' });

    const rawQueue = await redis.lRange(QUEUE_KEY, 0, -1);
    const orders = rawQueue
      .map(s => { try { return normalizeRecord(JSON.parse(s)); } catch { return null; } })
      .filter(Boolean);

    const nameSet = new Set(names);
    const toProcess = orders.filter(o => nameSet.has(o.name));
    if (!toProcess.length) return res.status(404).json({ error: 'No matching orders found' });

    // Aggregate SKUs
    const agg = {};
    for (const o of toProcess) {
      for (const it of (o.items || [])) {
        const sku = it?.sku;
        const qty = Number(it?.qty || 0);
        if (!sku || !Number.isFinite(qty) || qty <= 0) continue;
        agg[sku] = (agg[sku] || 0) + qty;
      }
    }
    const skus = Object.keys(agg);
    if (!skus.length) return res.status(400).json({ error: 'No SKUs found to submit (missing SKUs on line items?)' });

    const {
      SS_ACCOUNT_NUMBER,
      SS_API_KEY,
      SS_PAYMENT_PROFILE_ID,
      SS_PAYMENT_PROFILE_EMAIL,
    } = process.env;

    if (!SS_ACCOUNT_NUMBER || !SS_API_KEY) {
      return res.status(500).json({ error: 'Missing SS_ACCOUNT_NUMBER or SS_API_KEY on server' });
    }
    if (!SS_PAYMENT_PROFILE_ID || !SS_PAYMENT_PROFILE_EMAIL) {
      return res.status(500).json({ error: 'Missing SS_PAYMENT_PROFILE_ID or SS_PAYMENT_PROFILE_EMAIL on server' });
    }

    const auth = 'Basic ' + Buffer.from(`${SS_ACCOUNT_NUMBER}:${SS_API_KEY}`).toString('base64');

    // Best-effort subtotal: do not hard-fail if pricing fields vary
    let subtotal = 0;
    const priceWarnings = [];

    for (const [sku, qty] of Object.entries(agg)) {
      const r = await fetch(
        `https://api.ssactivewear.com/v2/products/${encodeURIComponent(sku)}?mediatype=json`,
        { headers: { Authorization: auth, Accept: 'application/json' } }
      );

      const js = await r.json().catch(() => ({}));
      if (!r.ok) {
        throw new Error(`S&S product lookup failed for ${sku}: ${r.status} ${JSON.stringify(js)}`);
      }

      // S&S may return an array; pricing fields vary by endpoint/version
      const p = Array.isArray(js) ? js[0] : js;

      const raw =
        p?.customerPrice ?? p?.CustomerPrice ??
        p?.piecePrice ?? p?.PiecePrice ??
        p?.salePrice ?? p?.SalePrice ??
        p?.casePrice ?? p?.CasePrice ??
        p?.Price ?? p?.price ??
        null;

      // Handles weird values like "12.31T00:00:00" by parsing the leading number
      const parsed = raw == null ? NaN : parseFloat(String(raw));

      if (Number.isFinite(parsed)) {
        subtotal += parsed * qty;
      } else {
        priceWarnings.push({ sku, raw });
      }
    }

    const payload = {
      customer: `Batch of ${toProcess.length} orders`,
      testOrder: true,
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
      Lines: Object.entries(agg).map(([Identifier, Qty]) => ({ Identifier, Qty })),
      PaymentProfile: {
        ProfileID: parseInt(SS_PAYMENT_PROFILE_ID, 10),
        Email: SS_PAYMENT_PROFILE_EMAIL,
      },
    };

    const resp = await fetch('https://api.ssactivewear.com/v2/orders/', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': auth,
        'Accept': 'application/json',
      },
      body: JSON.stringify(payload),
    });

    const json = await resp.json().catch(() => ({}));
    if (!resp.ok) {
      throw new Error(`S&S order create failed: ${resp.status} ${JSON.stringify(json)}`);
    }

    const created = json.orders?.[0];
    if (!created?.orderNumber) {
      throw new Error(`Batch failed: ${JSON.stringify(json)}`);
    }

    return res.json({
      ok: true,
      orderNumber: created.orderNumber,
      count: toProcess.length,
      subtotal: Number(subtotal.toFixed(2)),
      skuCount: skus.length,
      priceWarnings, // optional debug info; can remove later
    });
  } catch (err) {
    return res.status(500).json({ error: err?.message || String(err) });
  }
});


// ─── Start server ──────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Listening on port ${PORT}`));
