const express = require('express');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const app = express();

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const SECRET_KEY = process.env.SECRET_KEY || 'tramway_secret_pfe_2024';
const ADMIN_KEY = process.env.ADMIN_KEY || 'admin_tram_2024';
const QR_INTERVAL = 15;
const TICKET_TTL = 60 * 60;
const DB_FILE = path.join(__dirname, 'users.json');

function readDB() {
  if (!fs.existsSync(DB_FILE)) fs.writeFileSync(DB_FILE, JSON.stringify({ cards: [] }));
  return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
}
function writeDB(data) {
  fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
}

const activeTickets = new Map();

function hmacSign(data, key) {
  key = key || SECRET_KEY;
  return crypto.createHmac('sha256', key).update(String(data)).digest('hex');
}
function generateTOTP(ticketId, timeStep) {
  var step = timeStep !== undefined ? timeStep : Math.floor(Date.now() / 1000 / QR_INTERVAL);
  return hmacSign(ticketId + ':' + step).substring(0, 32);
}
function getCurrentTimeStep() {
  return Math.floor(Date.now() / 1000 / QR_INTERVAL);
}
function secondsUntilNextRotation() {
  var now = Math.floor(Date.now() / 1000);
  return QR_INTERVAL - (now % QR_INTERVAL);
}

// ── PAGE PRINCIPALE ──
app.get('/', function(req, res) {
  res.sendFile(path.join(__dirname, 'public/index.html'));
});

// ── ADMIN: ENREGISTRER CARTE ──
app.post('/api/admin/register-card', function(req, res) {
  var body = req.body;
  if (body.adminKey !== ADMIN_KEY) {
    return res.status(403).json({ error: 'Accès refusé' });
  }

  var cardNumber = String(body.cardNumber).replace(/\s/g, '');
  var ownerName = body.ownerName || 'Usager';

  if (!cardNumber) return res.status(400).json({ error: 'cardNumber manquant' });

  var db = readDB();
  var cardHash = hmacSign(cardNumber);
  var cardLast4 = cardNumber.slice(-4);

  var exists = db.cards.find(function(c) { return c.cardHash === cardHash; });
  if (exists) return res.status(409).json({ error: 'Carte déjà enregistrée' });

  db.cards.push({
    id: crypto.randomBytes(8).toString('hex'),
    cardHash: cardHash,
    cardLast4: cardLast4,
    ownerName: ownerName,
    registeredAt: Date.now(),
    active: true
  });

  writeDB(db);
  res.json({ success: true, message: 'Carte enregistrée', cardLast4: cardLast4 });
});

// ── VALIDATION DEPUIS VALIDEUR/RASPBERRY ──
app.post('/api/validate', function(req, res) {
  var body = req.body;
  var cardNumber = String(body.cardNumber || '').replace(/\s/g, '');
  var amount = body.amount || '1.80';
  var line = body.line || 'T1';
  var station = body.station || 'Centre-Ville';

  if (!cardNumber) return res.status(400).json({ error: 'cardNumber manquant' });

  var db = readDB();
  var cardHash = hmacSign(cardNumber);
  var card = db.cards.find(function(c) { return c.cardHash === cardHash && c.active; });

  if (!card) {
    return res.status(403).json({
      error: 'Carte non autorisée',
      registered: false,
      message: 'Cette carte n\'est pas enregistrée pour le tramway'
    });
  }

  var ticketId = crypto.randomBytes(16).toString('hex');
  var issuedAt = Math.floor(Date.now() / 1000);
  var expiresAt = issuedAt + TICKET_TTL;
  var sessionId = crypto.randomBytes(8).toString('hex');

  var ticketData = {
    ticketId: ticketId,
    ownerName: card.ownerName,
    cardLast4: card.cardLast4,
    amount: amount,
    line: line,
    station: station,
    issuedAt: issuedAt,
    expiresAt: expiresAt,
    sessionId: sessionId
  };

  activeTickets.set(ticketId, ticketData);
  setTimeout(function() { activeTickets.delete(ticketId); }, TICKET_TTL * 1000);

  var payload = JSON.stringify({
    ticketId: ticketId,
    exp: expiresAt,
    sig: hmacSign(ticketId + ':' + expiresAt)
  });
  var accessToken = Buffer.from(payload).toString('base64');

  res.json({
    success: true,
    registered: true,
    ownerName: card.ownerName,
    accessToken: accessToken,
    ticketUrl: '/ticket/' + accessToken,
    expiresAt: expiresAt,
    ttlMinutes: 60
  });
});

// ── RÉCUPÉRER TICKET ──
app.get('/api/ticket/:token', function(req, res) {
  try {
    var raw = Buffer.from(req.params.token, 'base64').toString('utf8');
    var parsed = JSON.parse(raw);
    var ticketId = parsed.ticketId;
    var exp = parsed.exp;
    var sig = parsed.sig;

    if (hmacSign(ticketId + ':' + exp) !== sig) return res.status(403).json({ error: 'Token invalide' });

    var now = Math.floor(Date.now() / 1000);
    if (now > exp) return res.status(410).json({ error: 'Expiré', expired: true });

    var ticket = activeTickets.get(ticketId);
    if (!ticket) return res.status(404).json({ error: 'Ticket introuvable' });

    var result = Object.assign({}, ticket);
    result.qrToken = generateTOTP(ticketId, getCurrentTimeStep());
    result.nextRotationIn = secondsUntilNextRotation();
    result.remainingSeconds = exp - now;

    res.json(result);
  } catch(e) {
    res.status(400).json({ error: 'Token malformé' });
  }
});

// ── REFRESH QR ──
app.get('/api/qr-refresh/:token', function(req, res) {
  try {
    var raw = Buffer.from(req.params.token, 'base64').toString('utf8');
    var parsed = JSON.parse(raw);
    var ticketId = parsed.ticketId;
    var exp = parsed.exp;
    var sig = parsed.sig;

    if (hmacSign(ticketId + ':' + exp) !== sig) return res.status(403).json({ error: 'Invalide' });

    var now = Math.floor(Date.now() / 1000);
    if (now > exp) return res.status(410).json({ error: 'Expiré', expired: true });

    res.json({
      qrToken: generateTOTP(ticketId),
      nextRotationIn: secondsUntilNextRotation(),
      remainingSeconds: exp - now
    });
  } catch(e) {
    res.status(400).json({ error: 'Erreur' });
  }
});

// ── PAGE TICKET ──
app.get('/ticket/:token', function(req, res) {
  res.sendFile(path.join(__dirname, 'public/index.html'));
});

var PORT = process.env.PORT || 3000;
app.listen(PORT, function() {
  console.log('Serveur tram-pwa sur port ' + PORT);
});
