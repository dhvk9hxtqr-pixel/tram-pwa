const express = require('express');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const app = express();

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const SECRET_KEY = process.env.SECRET_KEY || 'tramway_secret_pfe_2024';
const QR_INTERVAL = 15;
const TICKET_TTL = 60 * 60;
const DB_FILE = path.join(__dirname, 'users.json');

// ── DATABASE JSON ──
function readDB() {
  if (!fs.existsSync(DB_FILE)) fs.writeFileSync(DB_FILE, JSON.stringify({ users: [] }));
  return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
}
function writeDB(data) {
  fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
}

const activeTickets = new Map();

function hmacSign(data, key) {
  key = key || SECRET_KEY;
  return crypto.createHmac('sha256', key).update(data).digest('hex');
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

// ── ROUTES ──

// Page principale
app.get('/', function(req, res) {
  res.sendFile(path.join(__dirname, 'public/index.html'));
});

// Inscription carte
app.post('/api/register', function(req, res) {
  var body = req.body;
  var cardNumber = body.cardNumber;
  var name = body.name;
  var phone = body.phone;

  if (!cardNumber || !name || !phone) {
    return res.status(400).json({ error: 'Données manquantes' });
  }

  var db = readDB();
  var cardLast4 = String(cardNumber).slice(-4);
  var cardHash = hmacSign(String(cardNumber));

  var exists = db.users.find(function(u) { return u.cardHash === cardHash; });
  if (exists) return res.status(409).json({ error: 'Carte déjà enregistrée' });

  var user = {
    id: crypto.randomBytes(8).toString('hex'),
    name: name,
    phone: phone,
    cardLast4: cardLast4,
    cardHash: cardHash,
    createdAt: Date.now()
  };

  db.users.push(user);
  writeDB(db);

  res.json({ success: true, message: 'Carte enregistrée', userId: user.id });
});

// Validation depuis valideur/Raspberry Pi
app.post('/api/validate', function(req, res) {
  var body = req.body;
  var cardNumber = body.cardNumber;
  var amount = body.amount || '1.80';
  var line = body.line || 'T1';
  var station = body.station || 'Centre-Ville';

  if (!cardNumber) return res.status(400).json({ error: 'cardNumber manquant' });

  var db = readDB();
  var cardHash = hmacSign(String(cardNumber));
  var user = db.users.find(function(u) { return u.cardHash === cardHash; });

  if (!user) return res.status(403).json({ error: 'Carte non enregistrée', registered: false });

  var ticketId = crypto.randomBytes(16).toString('hex');
  var issuedAt = Math.floor(Date.now() / 1000);
  var expiresAt = issuedAt + TICKET_TTL;
  var sessionId = crypto.randomBytes(8).toString('hex');

  var ticketData = {
    ticketId: ticketId,
    userId: user.id,
    name: user.name,
    cardLast4: user.cardLast4,
    amount: amount,
    line: line,
    station: station,
    issuedAt: issuedAt,
    expiresAt: expiresAt,
    sessionId: sessionId
  };

  activeTickets.set(ticketId, ticketData);
  setTimeout(function() { activeTickets.delete(ticketId); }, TICKET_TTL * 1000);

  var payload = JSON.stringify({ ticketId: ticketId, exp: expiresAt, sig: hmacSign(ticketId + ':' + expiresAt) });
  var accessToken = Buffer.from(payload).toString('base64');

  res.json({
    success: true,
    registered: true,
    userName: user.name,
    accessToken: accessToken,
    ticketUrl: '/ticket/' + accessToken,
    expiresAt: expiresAt,
    ttlMinutes: 60
  });
});

// Récupérer ticket
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

// Refresh QR
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

// Page ticket
app.get('/ticket/:token', function(req, res) {
  res.sendFile(path.join(__dirname, 'public/index.html'));
});

var PORT = process.env.PORT || 3000;
app.listen(PORT, function() {
  console.log('Serveur tram-pwa sur port ' + PORT);
});
