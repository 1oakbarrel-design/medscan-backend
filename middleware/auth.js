const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) { console.error('FATAL: JWT_SECRET missing in middleware'); }
const { userQ, rtQ } = require('../utils/database');
const crypto = require('crypto');
function safeUser(u) {
  if (!u) return null;
  const { password_hash, reset_token, reset_token_expires, stripe_customer_id, stripe_subscription_id, ai_calls_today, ai_calls_date, ...s } = u;
  return s;
}
function requireAuth(req, res, next) {
  try {
    const h = req.headers.authorization;
    if (!h?.startsWith('Bearer ')) return res.status(401).json({ error: 'Authentication required', code: 'NO_TOKEN' });
    const d = jwt.verify(h.split(' ')[1], process.env.JWT_SECRET);
    const user = userQ.byId.get(d.userId);
    if (!user) return res.status(401).json({ error: 'User not found' });
    userQ.updateLastSeen.run(user.id);
    req.user = safeUser(user);
    next();
  } catch(e) {
    if (e.name === 'TokenExpiredError') return res.status(401).json({ error: 'Token expired', code: 'TOKEN_EXPIRED' });
    res.status(401).json({ error: 'Invalid token' });
  }
}
function generateToken(userId) { return jwt.sign({ userId }, process.env.JWT_SECRET, { expiresIn: '15m' }); }
function generateRefreshToken(userId) {
  const raw = crypto.randomBytes(48).toString('hex');
  const hash = crypto.createHash('sha256').update(raw).digest('hex');
  rtQ.create.run(crypto.randomBytes(16).toString('hex'), userId, hash, new Date(Date.now() + 90*86400000).toISOString());
  return raw;
}
function rotateRefreshToken(raw) {
  const hash = crypto.createHash('sha256').update(raw).digest('hex');
  const stored = rtQ.find.get(hash);
  if (!stored) throw new Error('Invalid refresh token');
  rtQ.use.run(stored.id);
  return { access: generateToken(stored.user_id), refresh: generateRefreshToken(stored.user_id), userId: stored.user_id };
}
module.exports = { requireAuth, generateToken, generateRefreshToken, rotateRefreshToken, safeUser };
