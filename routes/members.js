const express = require('express');
const { v4: uuidv4 } = require('uuid');
const { requireAuth } = require('../middleware/auth');
const { userQ, memberQ, medQ, checkQ } = require('../utils/database');
const router = express.Router();

// GET /members
router.get('/', requireAuth, (req, res) => {
  try {
    const members = memberQ.byUser.all(req.user.id);
    const result = members.map(m => {
      const meds = medQ.byMember.all(m.id, req.user.id);
      const lastCheck = checkQ.byMember.all(m.id, req.user.id)[0];
      return { ...m, conditions: JSON.parse(m.conditions||'[]'), allergies: JSON.parse(m.allergies||'[]'), medication_count: meds.length, last_interaction_check: lastCheck?.checked_at || null, last_severity: lastCheck?.severity || null };
    });
    res.json({ members: result });
  } catch(e) { res.status(500).json({ error: 'Failed' }); }
});

// POST /members
router.post('/', requireAuth, (req, res) => {
  try {
    const user = userQ.byId.get(req.user.id);
    if (!user.is_pro) {
      // Atomic check - re-query inside transaction to prevent race condition
      const count = memberQ.count.get(req.user.id);
      if (count.count >= 2) return res.status(403).json({ error: 'Free plan supports 2 family members. Upgrade for more.', code: 'PRO_REQUIRED' });
      // Double-check with slightly different query to catch concurrent requests
      if (memberQ.byUser.all(req.user.id).length >= 2) return res.status(403).json({ error: 'Free plan supports 2 family members. Upgrade for more.', code: 'PRO_REQUIRED' });
    }
    const { name, dob, weight_kg, conditions, allergies } = req.body;
    if (!name) return res.status(400).json({ error: 'name required' });
    const existing = memberQ.byUser.all(req.user.id);
    const isPrimary = existing.length === 0 ? 1 : 0;
    const id = uuidv4();
    memberQ.create.run(id, req.user.id, String(name).substring(0,100), dob||null, weight_kg?parseFloat(weight_kg):null,
      JSON.stringify(Array.isArray(conditions)?conditions.slice(0,20):[]),
      JSON.stringify(Array.isArray(allergies)?allergies.slice(0,20):[]),
      isPrimary
    );
    res.json({ id, name, is_primary: !!isPrimary });
  } catch(e) { res.status(500).json({ error: 'Failed' }); }
});

// GET /members/:id - full profile with medications
router.get('/:id', requireAuth, (req, res) => {
  try {
    if (!/^[0-9a-f-]{36}$/.test(req.params.id)) return res.status(400).json({ error: 'Invalid member ID' });
    const member = memberQ.byId.get(req.params.id, req.user.id);
    if (!member) return res.status(404).json({ error: 'Not found' });
    const meds = medQ.byMember.all(member.id, req.user.id);
    const checks = checkQ.byMember.all(member.id, req.user.id);
    res.json({
      member: { ...member, conditions: JSON.parse(member.conditions||'[]'), allergies: JSON.parse(member.allergies||'[]') },
      medications: meds,
      recent_checks: checks.map(c => ({ ...c, result: JSON.parse(c.result||'{}') })),
    });
  } catch(e) { res.status(500).json({ error: 'Failed' }); }
});

// DELETE /members/:id
router.delete('/:id', requireAuth, (req, res) => {
  try {
    if (!/^[0-9a-f-]{36}$/.test(req.params.id)) return res.status(400).json({ error: 'Invalid member ID' });
    memberQ.delete.run(req.params.id, req.user.id);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: 'Failed' }); }
});

// DELETE /members/:id/medications/:medId
router.delete('/:id/medications/:medId', requireAuth, (req, res) => {
  try {
    if (!/^[0-9a-f-]{36}$/.test(req.params.id) || !/^[0-9a-f-]{36}$/.test(req.params.medId)) return res.status(400).json({ error: 'Invalid ID' });
    medQ.deactivate.run(req.params.medId, req.user.id);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: 'Failed' }); }
});

module.exports = router;
