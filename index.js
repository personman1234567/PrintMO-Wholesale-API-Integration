// require('dotenv').config();
// const express = require('express');
// const crypto  = require('crypto');
// const fetch   = require('node-fetch').default;

// const app = express();
// app.use(express.raw({ type: 'application/json' }));

// // Load all your secrets (including your payment profile)
// const {
//   SHOPIFY_WEBHOOK_SECRET,
//   SS_ACCOUNT_NUMBER,
//   SS_API_KEY,
//   SS_PAYMENT_PROFILE_ID,
//   SS_PAYMENT_PROFILE_EMAIL
// } = process.env;

// // (Optional) Shopify HMAC verification
// function verifyShopifyWebhook(req) {
//   const hmacHeader    = req.get('X-Shopify-Hmac-Sha256');
//   const computedHmac  = crypto
//     .createHmac('sha256', SHOPIFY_WEBHOOK_SECRET)
//     .update(req.body, 'utf8')
//     .digest('base64');
//   return crypto.timingSafeEqual(Buffer.from(computedHmac), Buffer.from(hmacHeader));
// }

// app.post('/webhooks/orders/create', async (req, res) => {
//   console.log('💥 Webhook hit:', new Date().toISOString());

//   // Uncomment to enforce Shopify signature check
//   if (!verifyShopifyWebhook(req)) return res.status(401).send('Invalid signature');

//   let order;
//   try {
//     order = JSON.parse(req.body.toString());
//   } catch (err) {
//     console.error('❌ JSON parse error:', err);
//     return res.status(400).send('Bad JSON');
//   }
//   console.log(`📦 Received order ${order.name} (${order.line_items.length} items)`);

//   // Our Address to be shipped to
//   const shopAddress = {
//     name:     'LoGo Fishin Attn: TJ Reid',
//     address1: '328 Bristlecone ct s',
//     city:     'Saint Charles',
//     province: 'MO',
//     zip:      '63304',
//     country:  'USA'
//   };

//   // Build the S&S draft‐order payload
//   const payload = {
//     customer:            order.name,
//     testOrder:           true,
//     autoSelectWarehouse: true,
//     rejectLineErrors:    false,
//     shippingAddress: {
//       Name:    shopAddress.name,
//       Address: shopAddress.address1,
//       City:    shopAddress.city,
//       State:   shopAddress.province,
//       Zip:     shopAddress.zip,
//       Country: shopAddress.country
//     },
//     Lines: order.line_items
//       .filter(li => li.sku && li.sku.trim())
//       .map(li => ({ Identifier: li.sku, Qty: li.quantity })),
//     PaymentProfile: {
//       ProfileID: parseInt(SS_PAYMENT_PROFILE_ID, 10),
//       Email:     SS_PAYMENT_PROFILE_EMAIL
//     }
//   };

//   console.log('🚀 Sending payload to S&S:', payload);

//   // Send the draft‐order to S&S
//   const authHeader = 'Basic ' + Buffer
//     .from(`${SS_ACCOUNT_NUMBER}:${SS_API_KEY}`)
//     .toString('base64');

//   try {
//     const resSS   = await fetch('https://api.ssactivewear.com/v2/orders/', {
//       method:  'POST',
//       headers: {
//         'Content-Type':  'application/json',
//         'Authorization': authHeader
//       },
//       body: JSON.stringify(payload)
//     });
//     const ssResp = await resSS.json();
//     console.log('📤 S&S response:', ssResp);

//     // S&S returns an "orders" array, so grab the first one:
//     if (!Array.isArray(ssResp.orders) || ssResp.orders.length === 0) {
//       console.error('❌ No orders array in response:', ssResp);
//       return res.status(400).send('Failed to create draft');
//     }

//     const created = ssResp.orders[0];
//     if (!created.orderNumber) {
//       console.error('❌ No orderNumber in created order:', created);
//       return res.status(400).send('Failed to create draft');
//     }

//     console.log('✅ Draft order #', created.orderNumber);
//     res.status(200).send(`S&S draft order #${created.orderNumber} created`);
//   } catch (err) {
//     console.error('❌ Integration error:', err);
//     res.status(500).send('Error processing webhook');
//   }
// });

// const PORT = process.env.PORT || 3000;
// app.listen(PORT, () => console.log(`Listening on port ${PORT}`));

//------------------------------------------------------------------------------------------------

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

// 1) Queue each incoming Shopify order
app.post('/webhooks/orders/create', (req, res) => {
  console.log('💥 Webhook hit:', new Date().toISOString());

  // Uncomment to enforce signature:
  if (!verifyShopifyWebhook(req)) return res.status(401).send('Invalid signature');

  let order;
  try {
    order = JSON.parse(req.body.toString());
  } catch (err) {
    console.error('❌ JSON parse error:', err);
    return res.status(400).send('Bad JSON');
  }

  const items = order.line_items
    .filter(li => li.sku && li.sku.trim())
    .map(li => ({ sku: li.sku, qty: li.quantity }));

  pendingOrders.push({ name: order.name, items, receivedAt: new Date().toISOString() });
  console.log(`📥 Queued order ${order.name}. Queue length: ${pendingOrders.length}`);

  res.status(200).send('Order queued');
});

// 2) Manual batch processing endpoint
app.post('/batch/process', async (req, res) => {
  if (pendingOrders.length === 0) {
    return res.status(400).send('Nothing to process');
  }

  // Aggregate SKUs
  const agg = {};
  pendingOrders.forEach(o =>
    o.items.forEach(({ sku, qty }) => (agg[sku] = (agg[sku] || 0) + qty))
  );

  // Hard-coded shop address
  const shopAddress = {
    name:     'LoGo Fishin Attn: TJ Reid',
    address1: '328 Bristlecone Ct S',
    city:     'Saint Charles',
    province: 'MO',
    zip:      '63304',
    country:  'USA'
  };

  // Build payload
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
    Lines: Object.entries(agg).map(([sku, qty]) => ({ Identifier: sku, Qty: qty })),
    PaymentProfile: {
      ProfileID: parseInt(SS_PAYMENT_PROFILE_ID, 10),
      Email:     SS_PAYMENT_PROFILE_EMAIL
    }
  };

  console.log('🚀 Sending BATCH to S&S:', payload);

  const auth = 'Basic ' + Buffer
    .from(`${SS_ACCOUNT_NUMBER}:${SS_API_KEY}`)
    .toString('base64');

  try {
    const resp = await fetch('https://api.ssactivewear.com/v2/orders/', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': auth },
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
    pendingOrders.length = 0;  // clear queue

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
  res.send(`
    <html>
      <body style="font-family:sans-serif;max-width:600px;margin:2rem auto">
        <h1>Process S&S Batch</h1>
        <p>Currently queued: <strong>${pendingOrders.length}</strong> orders</p>
        <form method="POST" action="/batch/process">
          <button style="padding:0.5rem 1rem;font-size:1rem">Send Batch to S&S</button>
        </form>
      </body>
    </html>
  `);
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Listening on port ${PORT}`));
