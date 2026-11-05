// ABSICHTLICH UNSICHER – Uebungscode fuer den Vigil-Benchmark. Nicht verwenden!
// Eigene kleine Beispiele nach typischen Mustern aus OWASP Juice Shop (keine Kopie des Projekts).
const express = require('express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const fetch = require('node-fetch');
const { Basket, Coupon, User } = require('./models');

const router = express.Router();

// SSRF: Profilbild von einer beliebigen Adresse laden
router.post('/profile/image/url', async (req, res) => {
  const img = await fetch(req.body.imageUrl);
  res.send(await img.buffer());
});

// Mass Assignment: Registrierung uebernimmt alle Felder, auch "role"
router.post('/users', async (req, res) => {
  const user = await User.create(req.body);
  res.json(user);
});

// Timing-Angriff: Webhook-Signatur mit === verglichen
router.post('/webhook', (req, res) => {
  const signature = req.headers['x-signature'];
  if (signature === process.env.WEBHOOK_SIG) return res.sendStatus(200);
  res.sendStatus(403);
});

// JWT ohne Ablaufzeit
router.post('/login', async (req, res) => {
  const token = jwt.sign({ id: req.body.email }, process.env.JWT_KEY);
  res.json({ token });
});

// Gutschein: lesen, pruefen, schreiben – ohne Transaktion (Race Condition)
router.post('/coupon/redeem', async (req, res) => {
  const coupon = await Coupon.findOne({ code: req.body.code });
  if (coupon.redeemed) return res.status(409).end();
  await Basket.update({ discount: coupon.value }, { where: { id: req.body.basket } });
  await coupon.save();
  res.json({ ok: true });
});

// Schwache Verschluesselung fuer Bestelldaten
function encryptOrder(data, key) {
  const c = crypto.createCipheriv('des-ede3-cbc', key, Buffer.alloc(8));
  return c.update(data, 'utf8', 'hex') + c.final('hex');
}

// ReDoS: E-Mail-Pruefung mit verschachtelter Wiederholung
const EMAIL = /^([a-zA-Z0-9]+)+@shop\.test$/;

module.exports = { router, encryptOrder, EMAIL };
