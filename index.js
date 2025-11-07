require('dotenv').config();
const express = require('express');
const crypto  = require('crypto');
const fetch   = require('node-fetch').default; // reserved for future use
const { createClient } = require('redis');

const app = express();
// parse raw JSON for webhooks, and form-encoded bodies for our UI
app.use(express.raw({ type: 'application/json' }));
app.use(express.urlencoded({ extended: true }));

// ─── Redis Setup ───────────────────────────────────────────────────────────────
const redis = createClient({ url: process.env.REDIS_URL });
redis.on('error', err => console.error('❌ Redis error', err));
redis.connect()
  .then(() => console.log('✅ Redis connected'))
  .catch(console.error);

const QUEUE_KEY = 'shopifyOrdersQueue';

// Load secrets (optional PUBLIC_R2_BASE if you want to force a host)
const { SHOPIFY_WEBHOOK_SECRET, PUBLIC_R2_BASE } = process.env;

// ─── Helpers ──────────────────────────────────────────────────────────────────
function verifyShopifyWebhook(req) {
  const hmacHeader = req.get('X-Shopify-Hmac-Sha256');
  if (!hmacHeader) return true; // allow local testing
  const computed = crypto
    .createHmac('sha256', SHOPIFY_WEBHOOK_SECRET)
    .update(req.body, 'utf8')
    .digest('base64');
  return crypto.timingSafeEqual(Buffer.from(computed, 'utf8'), Buffer.from(hmacHeader, 'utf8'));
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

function tryURL(u) { try { return new URL(u); } catch { return null; } }
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

  const baseOrigin = (PUBLIC_R2_BASE && PUBLIC_R2_BASE.replace(/\/+$/, '')) || u.origin;

  // Expected: /previews/2025-11-07/<designRef>/<rest...>
  const re = /^\/previews\/\d{4}-\d{2}-\d{2}\/([^/]+)\/(.+)$/;
  const m = u.pathname.match(re);

  let rest = '';
  if (m && m[2]) {
    // If the captured designRef doesn't match, still use the provided designRef; keep the remainder.
    rest = m[2];
  } else {
    // Fallback: just take the basename and let the rest be that file
    rest = basenameFromPath(u.pathname);
  }

  const key = `orders/${orderNumber}_${custSlug}/${designRef}/${rest}`;
  return { key, url: `${baseOrigin}/${key}`, rest };
}

// ─── Webhook ──────────────────────────────────────────────────────────────────
app.post('/webhooks/orders/paid', async (req, res) => {
  console.log(`\n[Webhook Triggered] orders/paid at ${new Date().toISOString()}`);
  if (!verifyShopifyWebhook(req)) return res.status(401).send('☠️ Unauthorized');

  const order = JSON.parse(req.body.toString());

  // Order context
  const orderNumber = String(order.order_number || order.name || order.id || '').replace('#', '') || 'order';
  const first = order?.customer?.first_name || order?.billing_address?.first_name || '';
  const last  = order?.customer?.last_name  || order?.billing_address?.last_name  || '';
  const customerName = `${first} ${last}`.trim() || 'Guest';
  const custSlug = slug(customerName || 'customer');

  // Price fields
  const subtotal = parseFloat(order.current_subtotal_price || order.subtotal_price || 0) || 0;
  const discount = parseFloat(order.total_discounts || order.current_total_discounts || 0) || 0;
  const total    = parseFloat(order.total_price || order.current_total_price || 0) || 0;

  let derivedAssets = 0;

  // Map every line_item and attach a promoted orders URL derived from preview URL
  const items = (order.line_items || []).map(li => {
    const unitPrice = parseFloat(li.price || '0') || 0;
    const qty       = li.quantity || 0;
    const props     = propertiesToMap(li);

    // designRef in properties (support both keys)
    const designRef  = (props['_designref'] || props['_design_ref'] || '').toString().trim();
    const previewUrl = (props['design_preview_url'] || props['design-preview-url'] || '').toString().trim();

    let assets = [];
    if (designRef && previewUrl) {
      const built = promotedUrlFromPreview(previewUrl, { orderNumber, custSlug, designRef });
      if (built) {
        const fileName = basenameFromPath(built.url);
        const ext  = extFromBasename(fileName);
        const side = sideFromBasename(fileName) || null;
        const role = li.sku ? 'mockup' : 'design';
        assets.push({ key: built.key, url: built.url, ext, side, role });
        derivedAssets++;
      }
    }

    return {
      title:    li.title || li.name,
      sku:      li.sku || null,
      qty,
      unitPrice,
      lineTotal: parseFloat((unitPrice * qty).toFixed(2)),
      variantId:    li.variant_id,
      variantTitle: li.variant_title || '',
      designRef: designRef || null,
      assets,
      _previewUrl: previewUrl || null
    };
  });

  // Build the enriched record
  const record = {
    name:       `${order.name} – ${customerName}`,
    orderNumber,
    customerSlug: custSlug,
    receivedAt: new Date().toISOString(),
    subtotal,
    discount,
    total,
    items
  };

  // Push to Redis
  await redis.rPush(QUEUE_KEY, JSON.stringify(record));
  console.log(`📥 Queued ${record.name} (subtotal $${subtotal.toFixed(2)}), assets derived: ${derivedAssets}`);
  res.status(200).send('Queued');
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Listening on port ${PORT}`));
