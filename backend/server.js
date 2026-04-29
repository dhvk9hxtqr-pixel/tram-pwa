const express = require('express');
const crypto = require('crypto');
const path = require('path');
const app = express();

app.use(express.json());
app.use(express.static(path.join(__dirname, '../frontend/public')));

const SECRET_KEY = process.env.SECRET_KEY || 'tramway_secret_pfe_2024';
const QR_INTERVAL = 30;
const TICKET_TTL = 60 * 60;

const activeTickets = new Map();

function generateTicketId() {
  return crypto.randomBytes(16).toString('hex');
}

function hmacSign(data, key) {
  key = key || SECRET_KEY;
  return crypto.createHmac('sha256', key).update(data).digest('hex');
}

function generateTOTP(ticketId, timeStep) {
  var step = timeStep !== undefined ? timeStep : Math.floor(Date.now() / 1000 / QR_INTERVAL);
  var payload = ticketId + ':' + step;
  return hmacSign(payload).substring(0, 32);
}

function getCurrentTimeStep() {
  return Math.floor(Date.now() / 1000 / QR_INTERVAL);
}

function secondsUntilNextRotation() {
  var now = Math.floor(Date.now() / 1000);
  return QR_INTERVAL - (now % QR_INTERVAL);
}

app.post('/api/validate', function(req, res) {
  var body = req.body;
  var cardLast4 = body.cardLast4 || '****';
  var amount = body.amount || '1.80';
  var line = body.line || 'T1';
  var station = body.station || 'Centre-Ville';

  var ticketId = generateTicketId();
  var issuedAt = Math.floor(Date.now() / 1000);
  var expiresAt = issuedAt + TICKET_TTL;
  var sessionId = crypto.randomBytes(8).toString('hex');

  var ticketData = {
    ticketId: ticketId,
    cardLast4: cardLast4,
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
    accessToken: accessToken,
    ticketUrl: '/ticket/' + accessToken,
    expiresAt: expiresAt,
    ttlMinutes: 60
  });
});

app.get('/api/ticket/:token', function(req, res) {
  try {
    var raw = Buffer.from(req.params.token, 'base64').toString('utf8');
    var parsed = JSON.parse(raw);
    var ticketId = parsed.ticketId;
    var exp = parsed.exp;
    var sig = parsed.sig;

    var expectedSig = hmacSign(ticketId + ':' + exp);
    if (sig !== expectedSig) return res.status(403).json({ error: 'Token invalide' });

    var now = Math.floor(Date.now() / 1000);
    if (now > exp) return res.status(410).json({ error: 'Expire', expired: true });

    var ticket = activeTickets.get(ticketId);
    if (!ticket) return res.status(404).json({ error: 'Ticket introuvable' });

    var qrToken = generateTOTP(ticketId, getCurrentTimeStep());
    var nextRotation = secondsUntilNextRotation();

    var result = Object.assign({}, ticket);
    result.qrToken = qrToken;
    result.nextRotationIn = nextRotation;
    result.remainingSeconds = exp - now;

    res.json(result);
  } catch(e) {
    res.status(400).json({ error: 'Token malforme' });
  }
});

app.get('/api/qr-refresh/:token', function(req, res) {
  try {
    var raw = Buffer.from(req.params.token, 'base64').toString('utf8');
    var parsed = JSON.parse(raw);
    var ticketId = parsed.ticketId;
    var exp = parsed.exp;
    var sig = parsed.sig;

    var expectedSig = hmacSign(ticketId + ':' + exp);
    if (sig !== expectedSig) return res.status(403).json({ error: 'Invalide' });

    var now = Math.floor(Date.now() / 1000);
    if (now > exp) return res.status(410).json({ error: 'Expire', expired: true });

    var qrToken = generateTOTP(ticketId);
    var nextRotation = secondsUntilNextRotation();

    res.json({
      qrToken: qrToken,
      nextRotationIn: nextRotation,
      remainingSeconds: exp - now
    });
  } catch(e) {
    res.status(400).json({ error: 'Erreur' });
  }
});

app.get('/ticket/:token', function(req, res) {
  res.sendFile(path.join(__dirname, '../frontend/public/index.html'));
});


var PORT = process.env.PORT || 3000;
app.listen(PORT, function() {
  console.log('Serveur demarre sur port ' + PORT);
});
