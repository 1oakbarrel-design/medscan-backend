const express = require('express');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const rateLimit = require('express-rate-limit');
const { db, userQ, rtQ } = require('../utils/database');
const { generateToken, generateRefreshToken, rotateRefreshToken, requireAuth, safeUser } = require('../middleware/auth');
const router = express.Router();
const authLimiter = rateLimit({ windowMs: 15*60*1000, max: 5 });
const signupLimiter = rateLimit({ windowMs: 60*60*1000, max: 5, keyGenerator: req => req.ip });

router.post('/signup', signupLimiter, async (req, res) => {
  try {
    const { email, password, name, gdpr_consent } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
    if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });
    if (!gdpr_consent) return res.status(400).json({ error: 'Please agree to the Privacy Policy' });
    const clean = email.trim().toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(clean)) return res.status(400).json({ error: 'Invalid email' });
    if (userQ.byEmail.get(clean)) return res.status(409).json({ error: 'Email already registered' });
    const userId = uuidv4();
    userQ.create.run(userId, clean, await bcrypt.hash(password, 12), name ? String(name).substring(0,100) : null, 1, new Date().toISOString());
    const user = userQ.byId.get(userId);
    res.status(201).json({ token: generateToken(userId), refresh_token: generateRefreshToken(userId), user: safeUser(user) });
  } catch(e) { console.error('Signup:', e); res.status(500).json({ error: 'Signup failed' }); }
});

router.post('/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
    const user = userQ.byEmail.get(email.trim().toLowerCase());
    const DUMMY = '$2a$12$dummy.hash.to.prevent.timing.attacks.xxxxxxxxxxxxxxxxxxx';
    const match = await bcrypt.compare(password, user ? user.password_hash : DUMMY);
    if (!user || !match) return res.status(401).json({ error: 'Invalid email or password' });
    res.json({ token: generateToken(user.id), refresh_token: generateRefreshToken(user.id), user: safeUser(user) });
  } catch(e) { res.status(500).json({ error: 'Login failed' }); }
});

router.post('/refresh', rateLimit({ windowMs: 15*60*1000, max: 20 }), async (req, res) => {
  try {
    const { refresh_token } = req.body;
    if (!refresh_token) return res.status(400).json({ error: 'refresh_token required' });
    const { access, refresh, userId } = rotateRefreshToken(refresh_token);
    res.json({ token: access, refresh_token: refresh, user: safeUser(userQ.byId.get(userId)) });
  } catch(e) { res.status(401).json({ error: 'Invalid or expired refresh token' }); }
});

router.get('/me', requireAuth, (req, res) => res.json({ user: req.user }));
router.post('/logout', requireAuth, (req, res) => { try { rtQ.revokeAll.run(req.user.id); res.json({ ok: true }); } catch(e) { res.status(500).json({ error: 'Failed' }); } });

router.post('/forgot-password', authLimiter, async (req, res) => {
  try {
    const user = req.body.email ? userQ.byEmail.get(req.body.email.trim().toLowerCase()) : null;
    if (user) userQ.setResetToken.run(crypto.randomBytes(32).toString('hex'), user.email);
    res.json({ message: 'If an account exists, a reset link has been sent.' });
  } catch(e) { res.status(500).json({ error: 'Failed' }); }
});

router.post('/reset-password', authLimiter, async (req, res) => {
  try {
    const { token, password } = req.body;
    if (!token || !password || password.length < 8) return res.status(400).json({ error: 'Valid token and password required' });
    const user = userQ.byResetToken.get(token);
    if (!user) return res.status(400).json({ error: 'Invalid or expired link' });
    userQ.clearResetToken.run(await bcrypt.hash(password, 12), user.id);
    rtQ.revokeAll.run(user.id);
    res.json({ message: 'Password updated' });
  } catch(e) { res.status(500).json({ error: 'Failed' }); }
});


router.delete('/account', requireAuth, rateLimit({ windowMs: 60*60*1000, max: 3, message: { error: 'Too many attempts' } }), async (req, res) => {
  try {
    const { password } = req.body;
    const user = userQ.byId.get(req.user.id);
    if (!await bcrypt.compare(password, user.password_hash)) return res.status(401).json({ error: 'Incorrect password' });
    if (user.stripe_subscription_id) {
      try { await require('stripe')(process.env.STRIPE_SECRET_KEY).subscriptions.cancel(user.stripe_subscription_id); } catch(e) { console.error('Stripe cancel:', e.message); }
    }
    rtQ.revokeAll.run(req.user.id);
    db.prepare('DELETE FROM medications WHERE user_id=?').run(req.user.id);
    db.prepare('DELETE FROM family_members WHERE user_id=?').run(req.user.id);
    db.prepare('DELETE FROM interaction_checks WHERE user_id=?').run(req.user.id);
    db.prepare('DELETE FROM scans WHERE user_id=?').run(req.user.id);
    db.prepare('DELETE FROM refresh_tokens WHERE user_id=?').run(req.user.id);
    db.prepare('DELETE FROM users WHERE id=?').run(req.user.id);
    res.json({ message: 'Account permanently deleted.' });
  } catch(e) { console.error('Delete account:', e); res.status(500).json({ error: 'Deletion failed. Please try again.' }); }
});

router.post('/admin/activate', async (req, res) => {
  try {
    const { email, secret } = req.body;
    const ADMIN_SECRET = process.env.ADMIN_SECRET || 'raj2025';
    if (secret !== ADMIN_SECRET) return res.status(403).json({ error: 'Invalid secret' });
    const user = userQ.byEmail.get((email || '').toLowerCase());
    if (!user) return res.status(404).json({ error: 'User not found' });
    db.prepare("UPDATE users SET is_admin=1,is_pro=1,plan='lifetime',subscription_status='lifetime' WHERE id=?").run(user.id);
    res.json({ success: true, message: `Admin + lifetime access granted to ${email}` });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

module.exports = router;
