/**

- Backend - Justificatif de voyage Tramway
- Sécurité : TOTP-like QR rotation + JWT + expiration 60min
  */

const express = require(‘express’);
const crypto = require(‘crypto’);
const path = require(‘path’);
const app = express();

app.use(express.json());
app.use(express.static(path.join(__dirname, ‘../frontend/public’)));

// ─── CONFIG ────────────────────────────────────────────────────────────────
const SECRET_KEY = process.env.SECRET_KEY || ‘tramway_secret_key_2024_billettique’;
const QR_INTERVAL = 30;     // secondes
const TICKET_TTL = 60 * 60; // 60 minutes en secondes

// ─── STOCKAGE EN MÉMOIRE (remplacer par Redis/DB en prod) ─────────────────
const activeTickets = new Map();

// ─── HELPERS ───────────────────────────────────────────────────────────────
function generateTicketId() {
return crypto.randomBytes(16).toString(‘hex’);
}

function hmacSign(data, key = SECRET_KEY) {
return crypto.createHmac(‘sha256’, key).update(data).digest(‘hex’);
}

/**

- TOTP-like : génère un token qui change toutes les 30s
- basé sur ticketId + tranche de temps
  */
  function generateTOTP(ticketId, timeStep = null) {
  const step = timeStep ?? Math.floor(Date.now() / 1000 / QR_INTERVAL);
  const payload = `${ticketId}:${step}`;
  return hmacSign(payload).substring(0, 32); // 32 chars hex
  }

function getCurrentTimeStep() {
return Math.floor(Date.now() / 1000 / QR_INTERVAL);
}

function secondsUntilNextRotation() {
const now = Math.floor(Date.now() / 1000);
return QR_INTERVAL - (now % QR_INTERVAL);
}

// ─── ROUTES API ────────────────────────────────────────────────────────────

/**

- POST /api/validate
- Simule la validation EMV par le VPE412
- Body: { cardLast4, amount, line, station }
  */
  app.post(’/api/validate’, (req, res) => {
  const { cardLast4 = ’****’, amount = ‘1.80’, line = ‘T1’, station = ‘Centre-Ville’ } = req.body;

const ticketId = generateTicketId();
const issuedAt = Math.floor(Date.now() / 1000);
const expiresAt = issuedAt + TICKET_TTL;

const ticketData = {
ticketId,
cardLast4: String(cardLast4).replace(/\d(?=\d{4})/g, ‘*’), // masque sauf 4 derniers
amount,
line,
station,
issuedAt,
expiresAt,
sessionId: crypto.randomBytes(8).toString(‘hex’),
};

activeTickets.set(ticketId, ticketData);

// Nettoyage auto après expiration
setTimeout(() => activeTickets.delete(ticketId), TICKET_TTL * 1000);

// Token d’accès signé
const accessToken = Buffer.from(JSON.stringify({
ticketId,
exp: expiresAt,
sig: hmacSign(`${ticketId}:${expiresAt}`)
})).toString(‘base64url’);

res.json({
success: true,
accessToken,
ticketUrl: `/ticket/${accessToken}`,
expiresAt,
ttlMinutes: TICKET_TTL / 60
});
});

/**

- GET /api/ticket/:token
- Retourne les données du ticket si valide
  */
  app.get(’/api/ticket/:token’, (req, res) => {
  try {
  const raw = Buffer.from(req.params.token, ‘base64url’).toString(‘utf8’);
  const { ticketId, exp, sig } = JSON.parse(raw);
  
  // Vérif signature
  const expectedSig = hmacSign(`${ticketId}:${exp}`);
  if (sig !== expectedSig) return res.status(403).json({ error: ‘Token invalide’ });
  
  // Vérif expiration
  const now = Math.floor(Date.now() / 1000);
  if (now > exp) return res.status(410).json({ error: ‘Justificatif expiré’, expired: true });
  
  const ticket = activeTickets.get(ticketId);
  if (!ticket) return res.status(404).json({ error: ‘Ticket introuvable’ });
  
  const timeStep = getCurrentTimeStep();
  const qrToken = generateTOTP(ticketId, timeStep);
  const nextRotation = secondsUntilNextRotation();
  
  res.json({
  …ticket,
  qrToken,           // token TOTP actuel pour le QR
  nextRotationIn: nextRotation,
  remainingSeconds: exp - now,
  });

} catch (e) {
res.status(400).json({ error: ‘Token malformé’ });
}
});

/**

- GET /api/qr-refresh/:token
- Endpoint léger pour récupérer uniquement le nouveau QR token
  */
  app.get(’/api/qr-refresh/:token’, (req, res) => {
  try {
  const raw = Buffer.from(req.params.token, ‘base64url’).toString(‘utf8’);
  const { ticketId, exp, sig } = JSON.parse(raw);
  
  const expectedSig = hmacSign(`${ticketId}:${exp}`);
  if (sig !== expectedSig) return res.status(403).json({ error: ‘Invalide’ });
  
  const now = Math.floor(Date.now() / 1000);
  if (now > exp) return res.status(410).json({ error: ‘Expiré’, expired: true });
  
  const qrToken = generateTOTP(ticketId);
  const nextRotation = secondsUntilNextRotation();
  
  res.json({
  qrToken,
  nextRotationIn: nextRotation,
  remainingSeconds: exp - now,
  });

} catch (e) {
res.status(400).json({ error: ‘Erreur’ });
}
});

/**

- GET /ticket/:token → sert le frontend SPA
  */
  app.get(’/ticket/:token’, (req, res) => {
  res.sendFile(path.join(__dirname, ‘../frontend/public/index.html’));
  });

// ─── DÉMARRAGE ─────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
console.log(`✅ Serveur démarré sur http://localhost:${PORT}`);
console.log(`📋 Test : POST /api/validate avec { cardLast4, amount, line, station }`);
});

module.exports = app;
