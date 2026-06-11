const express = require('express');
const rateLimit = require('express-rate-limit');
const { v4: uuidv4 } = require('uuid');
const fetch = require('node-fetch');
const { requireAuth } = require('../middleware/auth');
const { userQ, memberQ, medQ, scanQ, checkQ } = require('../utils/database');

const router = express.Router();
const limiter = rateLimit({ windowMs: 60000, max: 15 });
const FREE_SCANS_PER_MONTH = 3;

const DISCLAIMER = 'IMPORTANT: This is for informational purposes only. Always consult your pharmacist or doctor before making any medication decisions. This is not medical advice.';

const SCAN_PROMPT = `You are a medication label reading assistant. Extract information from the pill bottle/medication label image and return ONLY valid JSON.

Return this exact structure:
{
  "drug_name": "Brand name",
  "generic_name": "Generic/chemical name or null",
  "dosage": "e.g. 500mg",
  "dosage_form": "tablet/capsule/liquid/etc",
  "frequency": "e.g. twice daily",
  "purpose": "What this medication treats in plain English",
  "active_ingredients": ["ingredient1", "ingredient2"],
  "warnings": ["warning1", "warning2"],
  "common_side_effects": ["side effect1", "side effect2"],
  "do_not_take_with": ["food/drug to avoid"],
  "is_otc": true or false,
  "prescriber": "Doctor name if visible or null",
  "patient_name": "Patient name if visible or null",
  "confidence": 0.95
}

Rules:
- drug_name: the main name on the label
- purpose: plain English, max 20 words, no medical jargon
- warnings: most important only, max 5
- common_side_effects: most common only, max 5
- Return ONLY the JSON object, no markdown`;

const INTERACTION_PROMPT = `You are a medication interaction checker. Check for interactions between the listed medications and return ONLY valid JSON.

Medications to check: MEDICATIONS_LIST

Return this exact structure:
{
  "severity": "none|mild|moderate|severe",
  "interactions": [
    {
      "drug_a": "Drug name",
      "drug_b": "Drug name",
      "severity": "mild|moderate|severe",
      "description": "Plain English explanation of what happens",
      "recommendation": "What to do about it"
    }
  ],
  "summary": "One sentence plain English summary",
  "see_doctor": true or false
}

Rules:
- Only list real, clinically significant interactions
- Use plain English, no medical jargon
- If no interactions, return severity: none and empty interactions array
- Return ONLY the JSON object`;

// POST /scan/label - scan a medication label
router.post('/label', limiter, requireAuth, async (req, res) => {
  try {
    const { image_base64, mime_type, member_id } = req.body;
    if (!image_base64) return res.status(400).json({ error: 'image_base64 required' });
    if (typeof image_base64 !== 'string' || image_base64.length < 100) return res.status(400).json({ error: 'Invalid image' });
    const ALLOWED = ['image/jpeg','image/jpg','image/png','image/webp'];
    const safeMime = ALLOWED.includes(mime_type) ? mime_type : 'image/jpeg';
    const sizeBytes = Buffer.byteLength(image_base64, 'base64');
    if (sizeBytes > 8 * 1024 * 1024) return res.status(400).json({ error: 'Image too large. Max 8MB.' });

    // Validate member belongs to user
    if (member_id) {
      if (!/^[0-9a-f-]{36}$/.test(member_id)) return res.status(400).json({ error: 'Invalid member ID' });
      const member = memberQ.byId.get(member_id, req.user.id);
      if (!member) return res.status(404).json({ error: 'Family member not found' });
    }

    // Free tier check
    const user = userQ.byId.get(req.user.id);
    if (!user.is_pro) {
      const count = scanQ.freeCount.get(req.user.id);
      if (count.count >= FREE_SCANS_PER_MONTH) return res.status(403).json({ error: 'You have used your 3 free scans this month. Upgrade to Pro for unlimited scanning.', code: 'LIMIT_REACHED' });
    }

    userQ.incrementAiCalls.run(req.user.id);

    const aiRes = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': process.env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({
        model: 'claude-haiku-4-5-20251001',
        max_tokens: 1000,
        system: SCAN_PROMPT,
        messages: [{ role: 'user', content: [
          { type: 'image', source: { type: 'base64', media_type: safeMime, data: image_base64 } },
          { type: 'text', text: 'Read this medication label and extract all information. Return JSON only.' }
        ]}]
      })
    });

    if (!aiRes.ok) throw new Error('AI unavailable');
    const aiData = await aiRes.json();
    const raw = aiData.content.map(b => b.text || '').join('').replace(/```json|```/g, '').trim();

    let parsed;
    try { parsed = JSON.parse(raw); }
    catch(e) { return res.status(422).json({ error: 'Could not read this label. Try a clearer photo with good lighting.' }); }

    // Save scan
    const scanId = uuidv4();
    scanQ.create.run(scanId, req.user.id, member_id || null, String(parsed.drug_name || '').substring(0, 200), JSON.stringify(parsed));

    // Auto-save to member's cabinet if member_id provided
    let medId = null;
    if (member_id) {
      medId = uuidv4();
      medQ.create.run(
        medId, req.user.id, member_id,
        String(parsed.drug_name || 'Unknown').substring(0, 200),
        parsed.generic_name ? String(parsed.generic_name).substring(0, 200) : null,
        parsed.dosage ? String(parsed.dosage).substring(0, 100) : null,
        parsed.frequency ? String(parsed.frequency).substring(0, 100) : null,
        parsed.purpose ? String(parsed.purpose).substring(0, 300) : null,
        parsed.is_otc ? 1 : 0,
        user.is_pro ? image_base64 : null,
        parsed.drug_name ? String(parsed.drug_name).substring(0, 200) : null,
        null
      );
    }

    res.json({
      scan_id: scanId,
      medication_id: medId,
      ...parsed,
      disclaimer: DISCLAIMER,
      is_pro: !!user.is_pro,
    });
  } catch(e) {
    console.error('Scan:', e.message);
    res.status(500).json({ error: 'Scan failed. Please try again.' });
  }
});

// POST /scan/interactions - check interactions for a member
router.post('/interactions', limiter, requireAuth, async (req, res) => {
  try {
    const { member_id } = req.body;
    if (!member_id || !/^[0-9a-f-]{36}$/.test(member_id)) return res.status(400).json({ error: 'Valid member_id required' });
    const member = memberQ.byId.get(member_id, req.user.id);
    if (!member) return res.status(404).json({ error: 'Member not found' });

    const meds = medQ.byMember.all(member_id, req.user.id);
    if (meds.length < 2) return res.json({ severity: 'none', interactions: [], summary: 'Add at least 2 medications to check for interactions.', see_doctor: false, disclaimer: DISCLAIMER });

    userQ.incrementAiCalls.run(req.user.id);

    const medList = meds.map(m => `${m.name}${m.generic_name ? ` (${m.generic_name})` : ''}${m.dosage ? ` ${m.dosage}` : ''}`).join(', ');
    const prompt = INTERACTION_PROMPT.replace('MEDICATIONS_LIST', medList);

    const aiRes = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': process.env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({
        model: 'claude-haiku-4-5-20251001',
        max_tokens: 800,
        messages: [{ role: 'user', content: prompt }]
      })
    });

    if (!aiRes.ok) throw new Error('AI unavailable');
    const aiData = await aiRes.json();
    const raw = aiData.content.map(b => b.text || '').join('').replace(/```json|```/g, '').trim();

    let result;
    try { result = JSON.parse(raw); }
    catch(e) { result = { severity: 'unknown', interactions: [], summary: 'Could not complete check. Please consult your pharmacist.', see_doctor: true }; }

    // Save check
    checkQ.create.run(uuidv4(), req.user.id, member_id, JSON.stringify(meds.map(m => m.name)), JSON.stringify(result), result.severity || 'none');

    res.json({ ...result, disclaimer: DISCLAIMER, medications_checked: meds.map(m => m.name), checked_at: new Date().toISOString() });
  } catch(e) {
    console.error('Interactions:', e.message);
    res.status(500).json({ error: 'Interaction check failed. Please try again.' });
  }
});

// GET /scan/history
router.get('/history', requireAuth, (req, res) => {
  try {
    const scans = scanQ.recent.all(req.user.id);
    res.json({ scans: scans.map(s => ({ ...s, result: JSON.parse(s.result || '{}') })) });
  } catch(e) { res.status(500).json({ error: 'Failed' }); }
});

module.exports = router;
