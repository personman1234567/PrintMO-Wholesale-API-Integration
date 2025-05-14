require('dotenv').config();
const express = require('express');
const crypto  = require('crypto');
const fetch   = require('node-fetch').default;
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

// Load secrets
const {
  SHOPIFY_WEBHOOK_SECRET
} = process.env;

// Shopify HMAC check (skips if no header for local/testing)
function verifyShopifyWebhook(req) {
  const hmacHeader = req.get('X-Shopify-Hmac-Sha256');
  if (!hmacHeader) return true;
  const computed = crypto
    .createHmac('sha256', SHOPIFY_WEBHOOK_SECRET)
    .update(req.body, 'utf8')
    .digest('base64');
  return crypto.timingSafeEqual(
    Buffer.from(computed, 'utf8'),
    Buffer.from(hmacHeader, 'utf8')
  );
}

app.post('/webhooks/orders/paid', async (req, res) => {
  if (!verifyShopifyWebhook(req)) {
    return res.status(401).send('☠️ Unauthorized');
  }

  const order = JSON.parse(req.body.toString());

  // Build the display name
  const customerName = order.customer
    ? `${order.customer.first_name || ''} ${order.customer.last_name || ''}`.trim()
    : 'Guest';

  // Grab Shopify's subtotal directly
  const subtotal = parseFloat(
    order.current_subtotal_price   // Shopify payload field
    || order.subtotal_price        // fallback
    || 0
  );

  // Map every line_item, tagging print items (no SKU) vs apparel
  const items = order.line_items.map(li => {
    return {
      title:    li.title || li.name,
      sku:      li.sku || null,
      qty:      li.quantity
    };
  });

  // Build the enriched record
  const record = {
    name:       `${order.name} – ${customerName}`,
    receivedAt: new Date().toISOString(),
    subtotal,
    items
  };

  // Push to Redis
  await redis.rPush(QUEUE_KEY, JSON.stringify(record));
  console.log(`📥 Queued ${record.name} (subtotal $${subtotal.toFixed(2)})`);
  res.status(200).send('Queued');
});


// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Listening on port ${PORT}`));
