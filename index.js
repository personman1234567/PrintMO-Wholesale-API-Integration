require('dotenv').config();
const express = require('express');
const crypto  = require('crypto');
const fetch   = require('node-fetch').default;

const app = express();
app.use(express.raw({ type: 'application/json' }));

// In-memory queue (swap for a DB in prod)
const pendingOrders = [];

// Load your secrets
const {
  SHOPIFY_WEBHOOK_SECRET,
  SS_ACCOUNT_NUMBER,
  SS_API_KEY,
  SS_PAYMENT_PROFILE_ID,
  SS_PAYMENT_PROFILE_EMAIL
} = process.env;

// Optional Shopify HMAC check
function verifyShopifyWebhook(req) {
  const hmacHeader   = req.get('X-Shopify-Hmac-Sha256');
  const computedHmac = crypto
    .createHmac('sha256', SHOPIFY_WEBHOOK_SECRET)
    .update(req.body, 'utf8')
    .digest('base64');
  return crypto.timingSafeEqual(Buffer.from(computedHmac), Buffer.from(hmacHeader));
}

// 1) When queuing each Shopify order, capture title + sku + qty
app.post('/webhooks/orders/create', async (req, res) => {
  const order = JSON.parse(req.body.toString());
  const record = {
    name:       order.name,
    receivedAt: new Date().toLocaleString(),
    items: order.line_items
      .filter(li => li.sku && li.sku.trim())
      .map(li => ({
        title: li.title || li.name,   // product name from Shopify
        sku:   li.sku,
        qty:   li.quantity
      }))
  };
  pendingOrders.push(record);
  console.log(`📥 Queued ${record.name} with ${record.items.length} items`);
  res.status(200).send('Queued');
});

// 2) Manual batch processing endpoint
app.post('/batch/process', async (req, res) => {
  if (pendingOrders.length === 0) {
    return res.status(400).send('Nothing to process');
  }

  // 1) Aggregate SKUs across all queued Shopify orders
  const agg = {};
  pendingOrders.forEach(o =>
    o.items.forEach(({ sku, qty }) => {
      agg[sku] = (agg[sku] || 0) + qty;
    })
  );

  // 2) Fetch live unit prices and compute subtotal
  const authHeader = 'Basic ' +
    Buffer.from(`${SS_ACCOUNT_NUMBER}:${SS_API_KEY}`).toString('base64');

  let subtotal = 0;
  for (const [sku, qty] of Object.entries(agg)) {
    // GET the product details for this SKU
    const prodRes = await fetch(
      `https://api.ssactivewear.com/v2/products/${encodeURIComponent(sku)}?mediatype=json`,
      { headers: { Authorization: authHeader, Accept: 'application/json' } }
    );
    const prodJson = await prodRes.json();

    // The Products API returns a "Price" field for each SKU :contentReference[oaicite:0]{index=0}&#8203;:contentReference[oaicite:1]{index=1}
    const unitPrice = prodJson.Price ?? prodJson.price;
    subtotal += unitPrice * qty;
  }
  console.log(`💰 Subtotal (before tax & shipping): $${subtotal.toFixed(2)}`);

  // 3) Build your normal batch payload
  const shopAddress = {
    name:     'LoGo Fishin Attn: TJ Reid',
    address1: '328 Bristlecone Ct S',
    city:     'Saint Charles',
    province: 'MO',
    zip:      '63304',
    country:  'USA'
  };

  const payload = {
    customer:            `Batch of ${pendingOrders.length} orders`,
    testOrder:           true,
    autoSelectWarehouse: true,
    rejectLineErrors:    false,
    shippingAddress: {
      Name:    shopAddress.name,
      Address: shopAddress.address1,
      City:    shopAddress.city,
      State:   shopAddress.province,
      Zip:     shopAddress.zip,
      Country: shopAddress.country
    },
    Lines: Object.entries(agg).map(([sku, qty]) => ({
      Identifier: sku,
      Qty:        qty
    })),
    PaymentProfile: {
      ProfileID: parseInt(SS_PAYMENT_PROFILE_ID, 10),
      Email:     SS_PAYMENT_PROFILE_EMAIL
    }
  };

  console.log('🚀 Sending BATCH to S&S:', payload);

  // 4) Fire it off
  try {
    const resp = await fetch('https://api.ssactivewear.com/v2/orders/', {
      method:  'POST',
      headers: {
        'Content-Type':  'application/json',
        'Authorization': authHeader
      },
      body:    JSON.stringify(payload)
    });
    const json = await resp.json();
    console.log('📤 S&S batch response:', json);

    const created = Array.isArray(json.orders) && json.orders[0];
    if (!created || !created.orderNumber) {
      console.error('❌ Batch creation failed:', json);
      return res.status(500).send('Failed to create batch');
    }

    const count = pendingOrders.length;
    pendingOrders.length = 0; // clear queue

    console.log(`✅ Batch draft #${created.orderNumber} from ${count} orders`);
    return res
      .status(200)
      .send(`Batch order #${created.orderNumber} created from ${count} queued orders`);
  } catch (err) {
    console.error('❌ Error during batch:', err);
    return res.status(500).send('Error processing batch');
  }
});

// 3) Simple web UI to trigger the batch
app.get('/batch/ui', (req, res) => {
  // Build HTML for each queued order
  const htmlOrders = pendingOrders.map(o => {
    const lines = o.items.map(i =>
      `<li>${i.title} (SKU ${i.sku}) × ${i.qty}</li>`
    ).join('');
    return `
      <div style="margin-bottom:1.5rem;padding:1rem;border:1px solid #ddd">
        <strong>Order ${o.name}</strong><br>
        <small>Received: ${o.receivedAt}</small>
        <ul>${lines}</ul>
      </div>
    `;
  }).join('') || '<p><em>No orders queued.</em></p>';

  // (Optional) Real-time price estimate:
  // You could call S&S’s Products API here—fetch price per SKU, multiply by qty, sum.
  // Budget a second or two for all the HTTP requests, then display “Subtotal: $XX.XX”.

  res.send(`
    <html><head><meta charset="utf-8"><title>Batch UI</title></head>
    <body style="font-family:sans-serif;max-width:700px;margin:2rem auto">
      <h1>S&S Batch</h1>
      <p><strong>${pendingOrders.length}</strong> orders pending</p>
      ${htmlOrders}
      <form method="POST" action="/batch/process">
        <button style="padding:0.75rem 1.5rem;font-size:1rem">
          Submit Order
        </button>
      </form>
    </body>
    </html>
  `);
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Listening on port ${PORT}`));
