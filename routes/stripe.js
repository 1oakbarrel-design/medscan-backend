const express = require('express');
const Stripe = require('stripe');
const { requireAuth } = require('../middleware/auth');
const { userQ, webhookQ } = require('../utils/database');
const router = express.Router();
const stripe = Stripe(process.env.STRIPE_SECRET_KEY || '');

router.post('/checkout', requireAuth, async (req, res) => {
  try {
    const { plan } = req.body;
    const user = userQ.byId.get(req.user.id);
    const priceId = plan === 'yearly' ? process.env.STRIPE_PRICE_YEARLY : process.env.STRIPE_PRICE_MONTHLY;
    if (!priceId) return res.status(400).json({ error: 'Invalid plan' });
    let customerId = user.stripe_customer_id;
    if (!customerId) { const c = await stripe.customers.create({ email: user.email, name: user.name||undefined, metadata: { user_id: user.id } }); customerId = c.id; }
    const session = await stripe.checkout.sessions.create({
      customer: customerId, payment_method_types: ['card'],
      line_items: [{ price: priceId, quantity: 1 }], mode: 'subscription',
      subscription_data: { trial_period_days: 7, metadata: { user_id: user.id, plan } },
      success_url: `${process.env.FRONTEND_URL}?pro=1`, cancel_url: `${process.env.FRONTEND_URL}?upgrade=cancelled`,
      allow_promotion_codes: true,
    });
    res.json({ checkout_url: session.url });
  } catch(e) { res.status(500).json({ error: 'Failed' }); }
});

router.post('/portal', requireAuth, async (req, res) => {
  try {
    const user = userQ.byId.get(req.user.id);
    if (!user.stripe_customer_id) return res.status(400).json({ error: 'No subscription' });
    const s = await stripe.billingPortal.sessions.create({ customer: user.stripe_customer_id, return_url: process.env.FRONTEND_URL });
    res.json({ portal_url: s.url });
  } catch(e) { res.status(500).json({ error: 'Failed' }); }
});

router.post('/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  let event;
  try { event = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], process.env.STRIPE_WEBHOOK_SECRET); }
  catch(e) { return res.status(400).send(`Webhook Error: ${e.message}`); }
  if (webhookQ.seen.get(event.id)) return res.json({ received: true, duplicate: true });
  webhookQ.record.run(event.id);
  try {
    if (['customer.subscription.created','customer.subscription.updated'].includes(event.type)) {
      const sub = event.data.object;
      const c = await stripe.customers.retrieve(sub.customer);
      const user = userQ.byEmail.get(c.email);
      if (user) { const active = ['active','trialing'].includes(sub.status); userQ.updatePro.run(active?1:0, active?(sub.metadata?.plan||'monthly'):'free', sub.customer, sub.id, sub.status, new Date(sub.current_period_end*1000).toISOString(), user.id); }
    } else if (event.type === 'customer.subscription.deleted') {
      userQ.deactivatePro.run(event.data.object.id);
    }
  } catch(e) { console.error('Webhook:', e); }
  res.json({ received: true });
});

module.exports = router;
