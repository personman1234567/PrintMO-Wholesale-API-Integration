const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const { createPhase2Data, canonicalStage } = require('../phase2-data');

class FakeRedis {
  constructor() {
    this.hashes = new Map();
    this.strings = new Map();
    this.zsets = new Map();
    this.sets = new Map();
    this.lists = new Map();
  }
  async hGetAll(key) { return { ...(this.hashes.get(key) || {}) }; }
  async hSet(key, values, value) {
    const current = this.hashes.get(key) || {};
    if (typeof values === 'string') current[values] = String(value);
    else Object.assign(current, Object.fromEntries(Object.entries(values).map(([name, entry]) => [name, String(entry)])));
    this.hashes.set(key, current);
    return 1;
  }
  async get(key) { return this.strings.get(key) || null; }
  async set(key, value) { this.strings.set(key, String(value)); return 'OK'; }
  async sAdd(key, values) { const set = this.sets.get(key) || new Set(); for (const value of Array.isArray(values) ? values : [values]) set.add(value); this.sets.set(key, set); return 1; }
  async sMembers(key) { return [...(this.sets.get(key) || new Set())]; }
  async sRem(key, value) { return this.sets.get(key)?.delete(value) ? 1 : 0; }
  async zAdd(key, entries) { const set = this.zsets.get(key) || new Map(); for (const entry of entries) set.set(entry.value, entry.score); this.zsets.set(key, set); return entries.length; }
  async zRem(key, value) { return this.zsets.get(key)?.delete(value) ? 1 : 0; }
  async zRange(key, start, end) {
    const values = [...(this.zsets.get(key) || new Map()).entries()].sort((a, b) => a[1] - b[1]).map(([value]) => value);
    return values.slice(start, end === -1 ? undefined : end + 1);
  }
  async zCard(key) { return (this.zsets.get(key) || new Map()).size; }
  async lRange(key, start, end) { const list = this.lists.get(key) || []; return list.slice(start, end === -1 ? undefined : end + 1); }
  async lLen(key) { return (this.lists.get(key) || []).length; }
  multi() {
    const operations = [];
    const chain = {};
    for (const method of ['hSet', 'set', 'sAdd', 'sRem', 'zAdd', 'zRem']) {
      chain[method] = (...args) => { operations.push([method, args]); return chain; };
    }
    chain.exec = async () => {
      const results = [];
      for (const [method, args] of operations) results.push(await this[method](...args));
      return results;
    };
    return chain;
  }
}

async function run() {
  const serverSource = fs.readFileSync(require.resolve('../index'), 'utf8');
  assert(!serverSource.includes('if (!hmacHeader) return true'), 'legacy Shopify webhook verification must fail closed');
  const adapterSource = fs.readFileSync(require.resolve('../phase2-data'), 'utf8');
  assert(adapterSource.indexOf("local prior = redis.call('GET', KEYS[5])") < adapterSource.indexOf('local current = tonumber'), 'idempotent retries must be resolved before version conflicts');
  assert(adapterSource.includes('`${prefix}:idempotency:${id}:${digest(idempotencyKey)}`'), 'idempotency keys must be scoped to an order');
  assert(adapterSource.includes("code = 'LEGACY_ORDER_NOT_FOUND'"), 'legacy-compatible writes must fail before changing v1 when the legacy order is missing');
  assert(adapterSource.includes("code = 'LEGACY_STAGE_UNSUPPORTED'"), 'completed stage must be rejected while the legacy board cannot represent it');
  assert(adapterSource.includes("redis.call('LSET', KEYS[6]"), 'production metadata and the legacy queue must be written in the same Redis script');
  assert(adapterSource.includes("numberFromName == legacyIdentifier"), 'legacy mirroring must support the deployed queue shape that lacks Shopify GIDs');
  assert(adapterSource.includes("broadcastQueueChanged('v1_production_mutation')"), 'mirrored production mutations must notify connected clients');

  const redis = new FakeRedis();
  const shop = 'printmo-test.myshopify.com';
  const prefix = `printmo:${shop}`;
  const gid = 'gid://shopify/Order/60129381';
  const legacy = {
    name: '#1001 – Fixture Customer', orderNumber: '1001', receivedAt: '2026-07-20T15:30:00Z',
    status: 'blanks', blanksOrdered: 1, bundle: 'Fixture Bundle', notes: 'Internal only', progress: 2,
    items: [{ qty: 2 }], attachments: [{ name: 'art.png', type: 'image/png', data: 'BASE64_MUST_NOT_BE_STORED' }]
  };
  redis.lists.set('shopifyOrdersQueue', [JSON.stringify(legacy)]);
  const digest = crypto.createHash('sha256').update('1001').digest('hex');
  redis.strings.set(`${prefix}:legacy_map:${digest}`, gid);

  const data = createPhase2Data({ redis });
  await data.projectOrder({
    shop, gid, legacy,
    commerce: {
      id: gid, displayName: '#1001', createdAt: legacy.receivedAt,
      commerce: { lineItems: [{ id: 'line-1', currentQuantity: 2 }] },
      sync: { fetchedAt: new Date().toISOString() }
    }
  });

  const hash = await redis.hGetAll(`${prefix}:order:60129381`);
  assert.equal(hash.stage, 'blanks_ordered');
  assert.equal(hash.bundle_id, 'Fixture Bundle');
  assert(!hash.assets.includes('BASE64_MUST_NOT_BE_STORED'), 'v1 metadata must never contain Base64 attachment bytes');
  assert((await redis.zRange(`${prefix}:active_orders`, 0, -1)).includes(gid));
  assert((await redis.zRange(`${prefix}:stage:blanks_ordered`, 0, -1)).includes(gid));

  await data.projectOrder({
    shop, gid,
    legacy: { status: 'received', name: legacy.name, receivedAt: legacy.receivedAt },
    preserveExistingStage: true
  });
  const reconciledHash = await redis.hGetAll(`${prefix}:order:60129381`);
  assert.equal(reconciledHash.stage, 'blanks_ordered', 'Shopify reconciliation must not reset production stage');

  const report = await data.runParity(shop);
  assert.equal(report.parityStatus, 'PASSED');
  assert.equal(report.unexplainedMismatchCount, 0);
  assert.equal(report.explainedQuarantineCount, 0);
  assert.equal(canonicalStage({ status: 'blanks', blanksOrdered: 0 }), 'blanks_cart');
  assert.equal(canonicalStage({ status: 'print' }), 'print');
  console.log('Render Phase 2 Redis adapter verification passed.');
}

if (require.main === module) run().catch(error => { console.error(error); process.exit(1); });
module.exports = { run };
