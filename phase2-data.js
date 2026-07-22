const express = require('express');
const crypto = require('crypto');

const STAGES = ['received', 'to_order', 'blanks_cart', 'blanks_ordered', 'print', 'completed'];
const STAGE_SET = new Set(STAGES);
const QUEUE_KEY = 'shopifyOrdersQueue';

const MUTATE_QUEUE_LUA = `
local spec = cjson.decode(ARGV[1])
local targets = {}
for _, name in ipairs(spec.orderNames or {}) do targets[name] = true end
local raw = redis.call('LRANGE', KEYS[1], 0, -1)
local updated = {}
for index, value in ipairs(raw) do
  local order = cjson.decode(value)
  local matches = targets[order.name] == true or (spec.bundleName and order.bundle == spec.bundleName)
  if matches then
    local patch = spec.patch or {}
    local allowed = {'status','blanksStatus','printsStatus','blanksOrdered','printsOrdered','bundle','notes','progress'}
    for _, field in ipairs(allowed) do
      if patch[field] ~= nil then order[field] = patch[field] end
    end
    if patch.addAttachment ~= nil then
      order.attachments = order.attachments or {}
      table.insert(order.attachments, patch.addAttachment)
    end
    if patch.removeAttachmentNames ~= nil then
      local remove = {}
      for _, name in ipairs(patch.removeAttachmentNames) do remove[name] = true end
      local kept = {}
      for _, attachment in ipairs(order.attachments or {}) do
        if not remove[attachment.name] then table.insert(kept, attachment) end
      end
      order.attachments = kept
    end
    redis.call('LSET', KEYS[1], index - 1, cjson.encode(order))
    table.insert(updated, order)
  end
end
return cjson.encode({success = true, count = #updated, updated = updated})`;

const DELETE_QUEUE_ITEM_LUA = `
local target = ARGV[1]
local raw = redis.call('LRANGE', KEYS[1], 0, -1)
for index, value in ipairs(raw) do
  local order = cjson.decode(value)
  if order.name == target then
    local tombstone = '__printmo_deleted__:' .. redis.call('TIME')[1] .. ':' .. index
    redis.call('LSET', KEYS[1], index - 1, tombstone)
    redis.call('LREM', KEYS[1], 1, tombstone)
    return cjson.encode(order)
  end
end
return ''`;

const APPEND_QUEUE_IF_MISSING_LUA = `
local incoming = cjson.decode(ARGV[1])
local raw = redis.call('LRANGE', KEYS[1], 0, -1)
for _, value in ipairs(raw) do
  local ok, existing = pcall(cjson.decode, value)
  if ok and ((incoming.admin_graphql_api_id and existing.admin_graphql_api_id == incoming.admin_graphql_api_id) or (incoming.name and existing.name == incoming.name)) then
    return 0
  end
end
redis.call('RPUSH', KEYS[1], ARGV[1])
return 1`;

const MUTATE_PRODUCTION_LUA = `
local prior = redis.call('GET', KEYS[5])
if prior then return prior end
local current = tonumber(redis.call('HGET', KEYS[1], '_v') or '0')
local expected = tonumber(ARGV[1])
if current ~= expected then
  return cjson.encode({ok = false, code = 'VERSION_CONFLICT', currentVersion = current})
end
local patch = cjson.decode(ARGV[2])
local allowed = {
  stage=true, bundle_id=true, internal_notes=true, printed_count=true,
  blanks_status=true, prints_status=true, prints_ordered=true, blanks_po=true,
  assets=true, production_snapshot=true, archived_at=true, archived_by=true
}
for field, value in pairs(patch) do
  if not allowed[field] then
    return cjson.encode({ok = false, code = 'INVALID_FIELD', field = field})
  end
  if value == cjson.null then redis.call('HDEL', KEYS[1], field)
  elseif type(value) == 'table' then redis.call('HSET', KEYS[1], field, cjson.encode(value))
  else redis.call('HSET', KEYS[1], field, tostring(value)) end
end
local newVersion = current + 1
redis.call('HSET', KEYS[1], '_v', tostring(newVersion), 'updated_at', ARGV[3])
redis.call('ZREM', KEYS[2], ARGV[4])
redis.call('ZREM', KEYS[3], ARGV[4])
if ARGV[5] == '1' then
  redis.call('ZADD', KEYS[4], ARGV[6], ARGV[4])
  redis.call('ZADD', KEYS[2], ARGV[6], ARGV[4])
else
  redis.call('ZREM', KEYS[4], ARGV[4])
end
local result = cjson.encode({ok = true, version = newVersion})
redis.call('SET', KEYS[5], result, 'EX', 86400)
return result`;

function safeShop(value) {
  const shop = String(value || '').trim().toLowerCase();
  if (!/^[a-z0-9][a-z0-9-]*\.myshopify\.com$/.test(shop)) throw new Error('Invalid Shopify shop domain');
  return shop;
}

function prefixFor(shop) {
  return `printmo:${safeShop(shop)}`;
}

function numericOrderId(value) {
  const match = /(?:gid:\/\/shopify\/Order\/)?(\d+)$/.exec(String(value || '').trim());
  return match ? match[1] : null;
}

function canonicalGid(value) {
  const id = numericOrderId(value);
  return id ? `gid://shopify/Order/${id}` : null;
}

function digest(value) {
  return crypto.createHash('sha256').update(String(value || '')).digest('hex');
}

function jsonParse(value, fallback = null) {
  if (value === null || value === undefined || value === '') return fallback;
  if (typeof value !== 'string') return value;
  try { return JSON.parse(value); } catch { return fallback; }
}

function canonicalStage(order = {}) {
  const raw = String(order.status || 'received');
  if (raw === 'toOrder' || raw === 'to_order') return 'to_order';
  if (raw === 'print' || raw === 'ready' || raw === 'printing') return 'print';
  if (raw === 'completed') return 'completed';
  if (raw === 'blanks_ordered') return 'blanks_ordered';
  if (raw === 'blanks_cart') return 'blanks_cart';
  if (raw === 'blanks') {
    const hasPo = Boolean(order.blanks_po || order.blanksPo || order.ss_order_id || order.ssOrderId);
    return hasPo || Number(order.blanksOrdered) === 1 ? 'blanks_ordered' : 'blanks_cart';
  }
  return 'received';
}

function legacyIdentifier(order = {}) {
  return String(order.orderNumber || order.name || order.id || '').trim();
}

function mappingCandidates(order = {}) {
  return [...new Set([
    order.admin_graphql_api_id,
    order.orderNumber,
    order.name,
    String(order.name || '').split(/[–-]/)[0].trim()
  ].filter(Boolean).map(String))];
}

function assetManifest(order = {}) {
  if (Array.isArray(order.v1Assets)) return order.v1Assets;
  const assets = [];
  for (const attachment of Array.isArray(order.attachments) ? order.attachments : []) {
    assets.push({
      legacy: true,
      name: String(attachment?.name || attachment?.filename || 'attachment'),
      contentType: attachment?.type || attachment?.contentType || null,
      byteSize: Number(attachment?.size || 0) || null,
      migrationState: attachment?.data || attachment?.base64 ? 'pending' : 'metadata_only'
    });
  }
  for (const item of Array.isArray(order.items) ? order.items : []) {
    for (const asset of Array.isArray(item?.assets) ? item.assets : []) {
      assets.push({
        legacy: true,
        name: String(asset?.name || String(asset?.key || '').split('/').pop() || 'asset'),
        objectKey: asset?.key || null,
        contentType: asset?.contentType || null,
        migrationState: asset?.key ? 'existing_object' : 'pending'
      });
    }
  }
  return assets;
}

function metadataFromHash(hash) {
  if (!hash || !Object.keys(hash).length) return null;
  return {
    id: hash.shopify_gid,
    stage: hash.stage || 'received',
    version: Number(hash._v || 0),
    createdAt: hash.created_at || null,
    bundleId: hash.bundle_id || null,
    blanksPo: jsonParse(hash.blanks_po, []),
    printedCount: Number(hash.printed_count || hash.progress || 0),
    blanksStatus: Number(hash.blanks_status || 0),
    printsStatus: Number(hash.prints_status || 0),
    printsOrdered: Number(hash.prints_ordered || 0),
    internalNotes: hash.internal_notes || '',
    assets: jsonParse(hash.assets, []),
    productionSnapshot: jsonParse(hash.production_snapshot),
    archivedAt: hash.archived_at || null,
    archivedBy: hash.archived_by || null,
    updatedAt: hash.updated_at || null,
    legacyIdentifier: hash.legacy_identifier || null
  };
}

function createPhase2Data({ redis, broadcastQueueChanged = () => {} }) {
  const router = express.Router();

  async function resolveLegacyGid(shop, order) {
    const direct = canonicalGid(order?.admin_graphql_api_id);
    if (direct) return direct;
    const prefix = prefixFor(shop);
    for (const candidate of mappingCandidates(order)) {
      const mapped = await redis.get(`${prefix}:legacy_map:${digest(candidate)}`);
      if (mapped) return canonicalGid(mapped);
    }
    return null;
  }

  async function storeMapping(shop, legacyKey, gid, ledger = {}) {
    const prefix = prefixFor(shop);
    const canonical = canonicalGid(gid);
    if (!legacyKey || !canonical) throw new Error('A legacy identifier and Shopify GID are required');
    await redis.multi()
      .set(`${prefix}:legacy_map:${digest(legacyKey)}`, canonical)
      .hSet(`${prefix}:migration:${digest(legacyKey)}`, {
        source_digest: digest(legacyKey),
        legacy_identifier: String(legacyKey),
        shopify_gid: canonical,
        match_result: ledger.matchResult || 'matched',
        migrated_at: ledger.migratedAt || new Date().toISOString(),
        asset_count: String(Number(ledger.assetCount || 0)),
        asset_checksums: JSON.stringify(ledger.assetChecksums || []),
        errors: JSON.stringify(ledger.errors || [])
      }).exec();
    return canonical;
  }

  async function projectOrder({ shop, gid, legacy = {}, commerce = null, preserveExistingStage = false }) {
    const canonical = canonicalGid(gid);
    const id = numericOrderId(canonical);
    if (!canonical || !id) throw new Error('A valid Shopify order GID is required');
    const prefix = prefixFor(shop);
    const orderKey = `${prefix}:order:${id}`;
    const existing = await redis.hGetAll(orderKey);
    const has = field => Object.prototype.hasOwnProperty.call(legacy, field);
    const stage = preserveExistingStage && existing.stage
      ? existing.stage
      : canonicalStage(legacy);
    const createdAt = commerce?.createdAt || existing.created_at || legacy.receivedAt || new Date().toISOString();
    const score = Number.isFinite(Date.parse(createdAt)) ? Date.parse(createdAt) : Date.now();
    const now = new Date().toISOString();
    const gidMember = canonical;
    const assets = has('v1Assets') || has('attachments')
      ? assetManifest(legacy)
      : jsonParse(existing.assets, []);
    const multi = redis.multi();
    multi.hSet(orderKey, {
      shopify_gid: canonical,
      stage,
      _v: existing._v || '1',
      created_at: createdAt,
      updated_at: now,
      legacy_identifier: legacyIdentifier(legacy),
      bundle_id: String(has('bundle') ? legacy.bundle : (existing.bundle_id || '')),
      internal_notes: String(has('notes') ? legacy.notes : (existing.internal_notes || '')),
      printed_count: String(Number(has('progress') ? legacy.progress : (existing.printed_count || 0))),
      blanks_status: String(Number(has('blanksStatus') ? legacy.blanksStatus : (existing.blanks_status || 0))),
      prints_status: String(Number(has('printsStatus') ? legacy.printsStatus : (existing.prints_status || 0))),
      prints_ordered: String(Number(has('printsOrdered') ? legacy.printsOrdered : (existing.prints_ordered || 0))),
      blanks_po: JSON.stringify(has('blanks_po') ? legacy.blanks_po : (has('blanksPo') ? legacy.blanksPo : jsonParse(existing.blanks_po, []))),
      assets: JSON.stringify(assets),
      production_snapshot: existing.production_snapshot || ''
    });
    for (const asset of assets) {
      if (!asset?.assetId) continue;
      multi.hSet(`${prefix}:asset:${asset.assetId}`, {
        asset_id: String(asset.assetId),
        order_gid: canonical,
        object_key: String(asset.objectKey || ''),
        name: String(asset.name || ''),
        content_type: String(asset.contentType || ''),
        byte_size: String(Number(asset.byteSize || 0)),
        sha256: String(asset.sha256 || '')
      });
    }
    for (const knownStage of STAGES) multi.zRem(`${prefix}:stage:${knownStage}`, gidMember);
    if (stage !== 'completed' && !existing.archived_at) {
      multi.zAdd(`${prefix}:stage:${stage}`, [{ score, value: gidMember }]);
      multi.zAdd(`${prefix}:active_orders`, [{ score, value: gidMember }]);
    } else {
      multi.zRem(`${prefix}:active_orders`, gidMember);
    }
    if (commerce) {
      const fetchedAt = commerce.fetchedAt || now;
      const cache = {
        ...commerce,
        fetchedAt,
        freshUntil: commerce.freshUntil || new Date(Date.parse(fetchedAt) + 60000).toISOString(),
        hardExpiresAt: commerce.hardExpiresAt || new Date(Date.parse(fetchedAt) + 86400000).toISOString(),
        stale: Boolean(commerce.stale),
        partial: Boolean(commerce.partial)
      };
      multi.set(`${prefix}:shopify_summary:${id}`, JSON.stringify(cache), { EX: 86400 });
    }
    await multi.exec();
    return { gid: canonical, stage, version: Number(existing._v || 1) };
  }

  async function projectMappedLegacyOrder(order, shop = process.env.SHOPIFY_SHOP_DOMAIN) {
    if (!shop) return false;
    const gid = await resolveLegacyGid(shop, order);
    if (!gid) return false;
    await projectOrder({ shop, gid, legacy: order });
    return true;
  }

  async function archiveMappedLegacyOrder(order, shop, actor = 'legacy-delete') {
    if (!shop) return false;
    const gid = await resolveLegacyGid(shop, order);
    if (!gid) return false;
    const prefix = prefixFor(shop);
    const id = numericOrderId(gid);
    const key = `${prefix}:order:${id}`;
    const existing = await redis.hGetAll(key);
    if (!Object.keys(existing).length) return false;
    const now = new Date().toISOString();
    const multi = redis.multi().hSet(key, {
      archived_at: now,
      archived_by: actor,
      updated_at: now,
      _v: String(Number(existing._v || 0) + 1)
    }).zRem(`${prefix}:active_orders`, gid);
    for (const stage of STAGES) multi.zRem(`${prefix}:stage:${stage}`, gid);
    await multi.exec();
    return true;
  }

  async function appendLegacyOrderIfMissing(order) {
    return Boolean(await redis.eval(APPEND_QUEUE_IF_MISSING_LUA, {
      keys: [QUEUE_KEY],
      arguments: [JSON.stringify(order)]
    }));
  }

  async function readQueue() {
    const raw = await redis.lRange(QUEUE_KEY, 0, -1);
    return raw.flatMap(value => {
      try { return [JSON.parse(value)]; } catch { return []; }
    });
  }

  router.get('/legacy/queue', async (_req, res) => {
    res.json(await readQueue());
  });

  router.post('/legacy/queue/mutate', async (req, res) => {
    const { orderName, orderNames, bundleName, patch } = req.body || {};
    if ((!orderName && !Array.isArray(orderNames) && !bundleName) || !patch || typeof patch !== 'object') {
      return res.status(400).json({ error: 'Mutation target and patch are required' });
    }
    const spec = {
      orderNames: [...new Set([...(Array.isArray(orderNames) ? orderNames : []), ...(orderName ? [orderName] : [])])],
      bundleName: bundleName || null,
      patch
    };
    const raw = await redis.eval(MUTATE_QUEUE_LUA, { keys: [QUEUE_KEY], arguments: [JSON.stringify(spec)] });
    const result = jsonParse(raw, { success: false, count: 0, updated: [] });
    const shop = req.get('X-Shopify-Shop-Domain') || process.env.SHOPIFY_SHOP_DOMAIN;
    Promise.allSettled((result.updated || []).map(order => projectMappedLegacyOrder(order, shop))).catch(() => {});
    broadcastQueueChanged('v1_legacy_mutation');
    res.json(result);
  });

  router.delete('/legacy/queue/item', async (req, res) => {
    const orderName = req.body?.orderName;
    if (!orderName) return res.status(400).json({ error: 'Missing orderName' });
    const raw = await redis.eval(DELETE_QUEUE_ITEM_LUA, { keys: [QUEUE_KEY], arguments: [String(orderName)] });
    if (!raw) return res.status(404).json({ success: false, message: 'Order not found' });
    const removed = jsonParse(raw);
    const shop = req.get('X-Shopify-Shop-Domain') || process.env.SHOPIFY_SHOP_DOMAIN;
    if (removed) await archiveMappedLegacyOrder(removed, shop);
    broadcastQueueChanged('v1_legacy_delete');
    res.json({ success: true, deleted: orderName });
  });

  router.get('/data/legacy', async (req, res) => {
    const limit = Math.min(Math.max(Number(req.query.limit || 10), 1), 25);
    const offset = Math.max(Number(req.query.offset || 0), 0);
    const raw = await redis.lRange(QUEUE_KEY, offset, offset + limit - 1);
    const records = raw.flatMap(value => {
      try { return [JSON.parse(value)]; } catch { return []; }
    });
    const total = await redis.lLen(QUEUE_KEY);
    res.json({ records, total, nextOffset: offset + raw.length < total ? offset + raw.length : null });
  });

  router.post('/data/mappings', async (req, res) => {
    const { shop, legacyKey, gid, ledger } = req.body || {};
    const canonical = await storeMapping(shop, legacyKey, gid, ledger);
    res.json({ ok: true, gid: canonical });
  });

  router.post('/data/project', async (req, res) => {
    const projected = await projectOrder(req.body || {});
    res.json({ ok: true, ...projected });
  });

  router.get('/data/orders', async (req, res) => {
    const shop = safeShop(req.query.shop);
    const prefix = prefixFor(shop);
    const stage = req.query.stage ? String(req.query.stage) : null;
    if (stage && !STAGE_SET.has(stage)) return res.status(400).json({ error: 'Invalid stage' });
    const limit = Math.min(Math.max(Number(req.query.limit || 50), 1), 50);
    const offset = Math.max(Number(req.query.offset || 0), 0);
    const indexKey = stage ? `${prefix}:stage:${stage}` : `${prefix}:active_orders`;
    const gids = await redis.zRange(indexKey, offset, offset + limit - 1);
    const records = await Promise.all(gids.map(async gid => {
      const id = numericOrderId(gid);
      const [hash, summary] = await Promise.all([
        redis.hGetAll(`${prefix}:order:${id}`),
        redis.get(`${prefix}:shopify_summary:${id}`)
      ]);
      return { gid, production: metadataFromHash(hash), summary: jsonParse(summary) };
    }));
    const total = await redis.zCard(indexKey);
    res.json({ records, total, nextOffset: offset + gids.length < total ? offset + gids.length : null });
  });

  router.get('/data/orders/:id', async (req, res) => {
    const shop = safeShop(req.query.shop);
    const id = numericOrderId(req.params.id);
    if (!id) return res.status(400).json({ error: 'Invalid order ID' });
    const prefix = prefixFor(shop);
    const [hash, summary, detail] = await Promise.all([
      redis.hGetAll(`${prefix}:order:${id}`),
      redis.get(`${prefix}:shopify_summary:${id}`),
      redis.get(`${prefix}:shopify_detail:${id}`)
    ]);
    if (!Object.keys(hash).length) return res.status(404).json({ error: 'Order not found' });
    res.json({ gid: canonicalGid(id), production: metadataFromHash(hash), summary: jsonParse(summary), detail: jsonParse(detail) });
  });

  router.patch('/data/orders/:id/production', async (req, res) => {
    const { shop, expectedVersion, patch, idempotencyKey, actor } = req.body || {};
    const id = numericOrderId(req.params.id);
    if (!id || !Number.isInteger(Number(expectedVersion)) || !patch || !idempotencyKey) {
      return res.status(400).json({ error: 'Order ID, expectedVersion, patch, and idempotencyKey are required' });
    }
    const prefix = prefixFor(shop);
    const gid = canonicalGid(id);
    const hash = await redis.hGetAll(`${prefix}:order:${id}`);
    if (!Object.keys(hash).length) return res.status(404).json({ error: 'Order not found' });
    const oldStage = hash.stage || 'received';
    const newStage = patch.stage || oldStage;
    if (!STAGE_SET.has(newStage)) return res.status(400).json({ error: 'Invalid stage' });
    const archivedAfter = Object.prototype.hasOwnProperty.call(patch, 'archived_at')
      ? patch.archived_at
      : hash.archived_at;
    const active = newStage !== 'completed' && !archivedAfter;
    const score = Number.isFinite(Date.parse(hash.created_at)) ? Date.parse(hash.created_at) : Date.now();
    const keys = [
      `${prefix}:order:${id}`,
      `${prefix}:active_orders`,
      `${prefix}:stage:${oldStage}`,
      `${prefix}:stage:${newStage}`,
      `${prefix}:idempotency:${id}:${digest(idempotencyKey)}`
    ];
    const raw = await redis.eval(MUTATE_PRODUCTION_LUA, {
      keys,
      arguments: [String(expectedVersion), JSON.stringify(patch), new Date().toISOString(), gid, active ? '1' : '0', String(score)]
    });
    const result = jsonParse(raw, { ok: false, code: 'UNKNOWN' });
    if (!result.ok && result.code === 'VERSION_CONFLICT') {
      return res.status(409).json({ error: { code: result.code, message: 'Production metadata changed on another client.', currentVersion: result.currentVersion } });
    }
    if (!result.ok) return res.status(400).json({ error: { code: result.code, message: 'Production mutation rejected.', details: result } });
    await redis.xAdd(`${prefix}:audit`, '*', {
      event_id: crypto.randomUUID(),
      actor: String(actor || 'worker'),
      action: 'production.patch',
      resource_gid: gid,
      version: String(result.version),
      changed_fields: JSON.stringify(Object.keys(patch)),
      timestamp: new Date().toISOString(),
      outcome: 'success'
    });
    res.json({ ok: true, version: result.version, production: metadataFromHash(await redis.hGetAll(keys[0])) });
  });

  router.post('/data/cache/summaries', async (req, res) => {
    const { shop, summaries } = req.body || {};
    if (!Array.isArray(summaries)) return res.status(400).json({ error: 'summaries must be an array' });
    const prefix = prefixFor(shop);
    const multi = redis.multi();
    for (const summary of summaries) {
      const id = numericOrderId(summary?.id);
      if (!id) continue;
      multi.set(`${prefix}:shopify_summary:${id}`, JSON.stringify(summary), { EX: 86400 });
      multi.sRem(`${prefix}:dirty_orders`, canonicalGid(id));
    }
    await multi.exec();
    res.json({ ok: true, count: summaries.length });
  });

  router.post('/data/cache/details', async (req, res) => {
    const { shop, detail } = req.body || {};
    const id = numericOrderId(detail?.id);
    if (!id) return res.status(400).json({ error: 'A detail order GID is required' });
    await redis.set(`${prefixFor(shop)}:shopify_detail:${id}`, JSON.stringify(detail), { EX: 900 });
    res.json({ ok: true });
  });

  router.post('/data/cache/dirty', async (req, res) => {
    const { shop, gids } = req.body || {};
    const prefix = prefixFor(shop);
    const valid = (Array.isArray(gids) ? gids : [gids]).map(canonicalGid).filter(Boolean);
    if (valid.length) await redis.sAdd(`${prefix}:dirty_orders`, valid);
    res.json({ ok: true, count: valid.length });
  });

  router.get('/data/assets/:assetId', async (req, res) => {
    const hash = await redis.hGetAll(`${prefixFor(req.query.shop)}:asset:${String(req.params.assetId)}`);
    if (!Object.keys(hash).length || !hash.object_key) return res.status(404).json({ error: 'Asset not found' });
    res.json({
      assetId: hash.asset_id,
      orderGid: hash.order_gid,
      objectKey: hash.object_key,
      name: hash.name,
      contentType: hash.content_type || null,
      byteSize: Number(hash.byte_size || 0) || null,
      sha256: hash.sha256 || null
    });
  });

  router.post('/data/quarantine', async (req, res) => {
    const { shop, sourceDigest, legacyIdentifier: identifier, reason, details } = req.body || {};
    const record = {
      sourceDigest: String(sourceDigest || digest(identifier)),
      legacyIdentifier: String(identifier || ''),
      reason: String(reason || 'UNMAPPED'),
      details: details || null,
      recordedAt: new Date().toISOString()
    };
    await redis.sAdd(`${prefixFor(shop)}:quarantine`, JSON.stringify(record));
    res.json({ ok: true });
  });

  router.post('/data/webhooks/dedupe', async (req, res) => {
    const { shop, webhookId } = req.body || {};
    if (!webhookId) return res.status(400).json({ error: 'webhookId is required' });
    const result = await redis.set(`${prefixFor(shop)}:webhook:${digest(webhookId)}`, '1', { NX: true, EX: 172800 });
    res.json({ accepted: result === 'OK' });
  });

  async function runParity(shop) {
    const orders = await readQueue();
    const prefix = prefixFor(shop);
    const mismatches = [];
    const mappedLegacyGids = new Set();
    let matched = 0;
    for (const legacy of orders) {
      const gid = await resolveLegacyGid(shop, legacy);
      const identifier = legacy.orderNumber || String(legacy.name || '').split(/[–-]/)[0].trim() || 'unknown';
      if (!gid) {
        mismatches.push({ orderIdentifier: identifier, fields: ['mapping'], reason: 'UNMAPPED_LEGACY_ORDER' });
        continue;
      }
      const id = numericOrderId(gid);
      mappedLegacyGids.add(gid);
      const [hash, summaryRaw] = await Promise.all([
        redis.hGetAll(`${prefix}:order:${id}`),
        redis.get(`${prefix}:shopify_summary:${id}`)
      ]);
      if (!Object.keys(hash).length) {
        mismatches.push({ orderIdentifier: identifier, fields: ['membership'], reason: 'MISSING_V1_METADATA' });
        continue;
      }
      const fields = [];
      if (canonicalStage(legacy) !== hash.stage) fields.push('stage');
      if (String(legacy.bundle || '') !== String(hash.bundle_id || '')) fields.push('bundle');
      if (String(legacy.notes || '') !== String(hash.internal_notes || '')) fields.push('notes');
      if (Number(legacy.progress || 0) !== Number(hash.printed_count || 0)) fields.push('progress');
      const manifest = jsonParse(hash.assets, []);
      const legacyAssetCount = assetManifest(legacy).length;
      if (legacyAssetCount !== manifest.length) fields.push('attachmentCount');
      const summary = jsonParse(summaryRaw);
      if (summary?.commerce?.lineItems) {
        const legacyQty = (legacy.items || []).reduce((sum, item) => sum + Number(item.qty || 0), 0);
        const liveQty = summary.commerce.lineItems.reduce((sum, item) => sum + Number(item.currentQuantity || 0), 0);
        if (legacyQty !== liveQty) fields.push('quantity');
      }
      if (fields.length) mismatches.push({ orderIdentifier: identifier, fields, reason: 'FIELD_MISMATCH' });
      else matched++;
    }
    const activeGids = await redis.zRange(`${prefix}:active_orders`, 0, -1);
    for (const gid of activeGids) {
      if (!mappedLegacyGids.has(gid)) {
        mismatches.push({ orderIdentifier: gid, fields: ['membership'], reason: 'EXTRA_V1_ACTIVE_ORDER' });
      }
    }
    const report = {
      checkedAt: new Date().toISOString(),
      legacyTotalCount: orders.length,
      v1MatchedCount: matched,
      unexplainedMismatchCount: mismatches.length,
      mismatches,
      parityStatus: mismatches.length ? 'MISMATCH' : 'PASSED'
    };
    await redis.hSet(`${prefix}:parity_reports`, report.checkedAt, JSON.stringify(report));
    return report;
  }

  router.post('/data/parity', async (req, res) => res.json(await runParity(req.body?.shop)));
  router.get('/data/parity/reports', async (req, res) => {
    const reports = await redis.hGetAll(`${prefixFor(req.query.shop)}:parity_reports`);
    res.json({ reports });
  });

  router.get('/data/checkpoint', async (req, res) => {
    const value = await redis.get(`${prefixFor(req.query.shop)}:reconcile_checkpoint`);
    res.json({ checkpoint: value || null });
  });
  router.post('/data/checkpoint', async (req, res) => {
    await redis.set(`${prefixFor(req.body?.shop)}:reconcile_checkpoint`, String(req.body?.checkpoint || new Date().toISOString()));
    res.json({ ok: true });
  });

  router.post('/data/integrity', async (req, res) => {
    const shop = safeShop(req.body?.shop);
    const prefix = prefixFor(shop);
    const gids = await redis.zRange(`${prefix}:active_orders`, 0, -1);
    let repaired = 0;
    for (const gid of gids) {
      const id = numericOrderId(gid);
      const hash = await redis.hGetAll(`${prefix}:order:${id}`);
      if (!Object.keys(hash).length || hash.archived_at || hash.stage === 'completed') {
        await redis.zRem(`${prefix}:active_orders`, gid);
        repaired++;
        continue;
      }
      for (const stage of STAGES) {
        if (stage !== hash.stage) await redis.zRem(`${prefix}:stage:${stage}`, gid);
      }
      await redis.zAdd(`${prefix}:stage:${hash.stage}`, [{ score: Date.parse(hash.created_at) || Date.now(), value: gid }]);
    }
    res.json({ ok: true, checked: gids.length, repaired });
  });

  return { router, projectMappedLegacyOrder, archiveMappedLegacyOrder, appendLegacyOrderIfMissing, projectOrder, runParity };
}

module.exports = {
  createPhase2Data,
  canonicalStage,
  canonicalGid,
  numericOrderId,
  metadataFromHash
};
