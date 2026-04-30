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
const DB_FILE = path.join(__dirname, 'db.json');

// ── DATABASE ──
function readDB() {
  if (!fs.existsSync(DB_FILE)) {
    fs.writeFileSync(DB_FILE, JSON.stringify({ users: [], tickets: [] }));
  }
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

// ── PAGES ──
app.get('/', function(req, res) {
  res.sendFile(path.join(__dirname, 'public/home.html'));
});
app.get('/register', function(req, res) {
  res.sendFile(path.join(__dirname, 'public/register.html'));
});
app.get('/login', function(req, res) {
  res.sendFile(path.join(__dirname, 'public/login.html'));
});
app.get('/dashboard', function(req, res) {
  res.sendFile(path.join(__dirname, 'public/dashboard.html'));
});
app.get('/ticket/:token', function(req, res) {
  res.sendFile(path.join(__dirname, 'public/ticket.html'));
});

// ── INSCRIPTION CLIENT ──
app.post('/api/register', function(req, res) {
  var body = req.body;
  var name = body.name;
  var email = body.email;
  var phone = body.phone;
  var cardNumber = String(body.cardNumber || '').replace(/\s/g, '');
  var password = body.password;

  if (!name || !email || !cardNumber || !password) {
    return res.status(400).json({ error: 'Champs manquants' });
  }

  var db = readDB();
  var cardHash = hmacSign(cardNumber);
  var emailExists = db.users.find(function(u) { return u.email === email; });
  var cardExists = db.users.find(function(u) { return u.cardHash === cardHash; });

  if (emailExists) return res.status(409).json({ error: 'Email déjà utilisé' });
  if (cardExists) return res.status(409).json({ error: 'Carte déjà enregistrée' });

  var user = {
    id: crypto.randomBytes(8).toString('hex'),
    name: name,
    email: email,
    phone: phone || '',
    cardHash: cardHash,
    cardLast4: cardNumber.slice(-4),
    passwordHash: hmacSign(password),
    createdAt: Date.now(),
    active: true
  };

  db.users.push(user);
  writeDB(db);

  res.json({ success: true, message: 'Compte créé', userId: user.id });
});

// ── LOGIN ──
app.post('/api/login', function(req, res) {
  var body = req.body;
  var email = body.email;
  var password = body.password;

  var db = readDB();
  var user = db.users.find(function(u) {
    return u.email === email && u.passwordHash === hmacSign(password);
  });

  if (!user) return res.status(401).json({ error: 'Email ou mot de passe incorrect' });
  if (!user.active) return res.status(403).json({ error: 'Compte désactivé' });

  var token = Buffer.from(JSON.stringify({
    userId: user.id,
    exp: Math.floor(Date.now() / 1000) + 86400,
    sig: hmacSign(user.id)
  })).toString('base64');

  res.json({
    success: true,
    token: token,
    name: user.name,
    cardLast4: user.cardLast4
  });
});

// ── VALIDATION DEPUIS VALIDEUR ──
app.post('/api/validate', function(req, res) {
  var body = req.body;
  var cardNumber = String(body.cardNumber || '').replace(/\s/g, '');
  var amount = body.amount || '1.80';
  var line = body.line || 'T1';
  var station = body.station || 'Centre-Ville';

  if (!cardNumber) return res.status(400).json({ error: 'cardNumber manquant' });

  var db = readDB();
  var cardHash = hmacSign(cardNumber);
  var user = db.users.find(function(u) { return u.cardHash === cardHash && u.active; });

  if (!user) {
    return res.status(403).json({
      error: 'Carte non enregistrée',
      registered: false,
      message: 'Carte non autorisée pour le tramway'
    });
  }

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

  var payload = JSON.stringify({
    ticketId: ticketId,
    exp: expiresAt,
    sig: hmacSign(ticketId + ':' + expiresAt)
  });
  var accessToken = Buffer.from(payload).toString('base64');

  res.json({
    success: true,
    registered: true,
    name: user.name,
    accessToken: accessToken,
    ticketUrl: '/ticket/' + accessToken,
    expiresAt: expiresAt
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

var PORT = process.env.PORT || 3000;
app.listen(PORT, function() {
  console.log('Serveur tram-pwa sur port ' + PORT);
});
