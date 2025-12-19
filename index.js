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
  methods: ['GET', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'X-Order-Manager-Key'],
};

// Apply CORS + preflight handling for all /order-manager routes
app.use('/order-manager', cors(corsOptions));
app.options('/order-manager/*', cors(corsOptions));

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
    // you can set this explicitly; UI also backfills if missing
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

      // 1) exact name match
      if (r.name === name) {
        foundIndex = i;
        rec = r;
        break;
      }

      // 2) normalized name match
      if (normalizeName(r.name) === reqNorm) {
        foundIndex = i;
        rec = r;
        break;
      }

      // 3) orderNumber match (more stable)
      if (reqOrderNumber && String(r.orderNumber) === String(reqOrderNumber)) {
        foundIndex = i;
        rec = r;
        break;
      }
    } catch {}
  }

  if (foundIndex === -1) {
    const sampleNames = [];
    for (let i = 0; i < Math.min(items.length, 5); i++) {
      try {
        sampleNames.push(JSON.parse(items[i])?.name);
      } catch {}
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

// ─── Start server ──────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Listening on port ${PORT}`));
