const crypto = require('node:crypto');

function createInventoryReadAuth({ inventoryReadKey, adminKey }) {
  const expected = inventoryReadKey || adminKey;
  const header = inventoryReadKey ? 'X-Inventory-Read-Key' : 'X-Order-Manager-Key';
  return (req, res, next) => {
    if (req.method === 'OPTIONS') return next();
    if (!expected) return res.status(500).json({ error: 'Missing inventory read key on server' });
    const actual = Buffer.from(req.get(header) || '');
    const wanted = Buffer.from(expected);
    if (actual.length !== wanted.length || !crypto.timingSafeEqual(actual, wanted)) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    next();
  };
}

module.exports = { createInventoryReadAuth };
