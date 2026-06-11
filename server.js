require('dotenv').config();
const REQUIRED = ['ANTHROPIC_API_KEY','JWT_SECRET','FRONTEND_URL','STRIPE_SECRET_KEY','STRIPE_WEBHOOK_SECRET'];
const missing = REQUIRED.filter(k => !process.env[k]);
if (missing.length) { console.warn('Warning - Missing vars (non-fatal):', missing.join(', ')); }
if ((process.env.JWT_SECRET||'').length < 32 && process.env.JWT_SECRET) { console.warn('JWT_SECRET should be 32+ chars'); }

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const app = express();
const PORT = process.env.PORT || 3003;

app.set('trust proxy', 1);
app.use(helmet({ crossOriginEmbedderPolicy: false }));
app.use(cors({ origin: true, credentials: true }));
app.use('/stripe/webhook', express.raw({ type: 'application/json' }));
app.use(express.json({ limit: '10mb' }));
app.use(rateLimit({ windowMs: 15*60*1000, max: 300 }));

app.use('/auth', require('./routes/auth'));
app.use('/scan', require('./routes/scan'));
app.use('/members', require('./routes/members'));
app.use('/stripe', require('./routes/stripe'));

app.get('/health', (_, res) => res.json({ status: 'ok', app: 'MedScan', version: '1.0.0' }));
app.use((_, res) => res.status(404).json({ error: 'Not found' }));
app.use((err, req, res, next) => { console.error(err); res.status(500).json({ error: 'Server error' }); });

if (!process.env.JWT_SECRET) { console.warn('JWT_SECRET not set — auth will fail'); }
app.listen(PORT, () => console.log(`\n💊 MedScan Backend v1.0\n   Port: ${PORT}\n`));
module.exports = app;
