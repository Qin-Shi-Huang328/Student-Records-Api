const crypto = require('crypto');

function readClaims(req) {
  const auth = req.header('authorization') || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  const [payload, signature] = token.split('.');
  if (!payload || !signature || !process.env.AUTH_SECRET) return null;
  const expected = crypto.createHmac('sha256', process.env.AUTH_SECRET).update(payload).digest();
  const supplied = Buffer.from(signature, 'base64url');
  if (expected.length !== supplied.length || !crypto.timingSafeEqual(expected, supplied)) return null;
  try {
    const claims = JSON.parse(Buffer.from(payload, 'base64url').toString());
    return claims.exp > Date.now() ? claims : null;
  } catch {
    return null;
  }
}

function getCaller(req) {
  if (process.env.API_KEY && req.header('x-api-key') === process.env.API_KEY) {
    return { type: 'service', name: 'service' };
  }
  return readClaims(req);
}

function requireRoles(...roles) {
  return (req, res, next) => {
    const caller = getCaller(req);
    if (!caller) return res.status(401).json({ error: 'Sign in or provide a valid API key' });
    req.caller = caller;
    if (caller.type === 'service') return next();
    if (caller.type === 'student' && roles.includes('student')) return next();
    if (caller.type === 'employee' && roles.includes(caller.role)) return next();
    return res.status(403).json({ error: 'Your account does not have permission for this action' });
  };
}

function requireSelfOrRoles(param, ...roles) {
  return (req, res, next) => {
    const caller = getCaller(req);
    if (!caller) return res.status(401).json({ error: 'Sign in or provide a valid API key' });
    req.caller = caller;
    if (caller.type === 'service') return next();
    if (caller.type === 'employee' && roles.includes(caller.role)) return next();
    if (caller.type === 'student' && caller.sid === req.params[param]) return next();
    return res.status(403).json({ error: 'Your account does not have permission for this action' });
  };
}

function actorName(req) {
  const c = req.caller;
  if (!c) return 'Unknown';
  if (c.type === 'service') return (req.header('x-changed-by') || 'service').trim().slice(0, 120);
  return String(c.name || c.sid).slice(0, 120);
}

module.exports = { readClaims, getCaller, requireRoles, requireSelfOrRoles, actorName };
