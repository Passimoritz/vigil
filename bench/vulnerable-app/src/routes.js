const express = require('express');
const { exec } = require('child_process');
const jwt = require('jsonwebtoken');
const _ = require('lodash');
const { findUser } = require('./db');

const app = express();
app.use(express.json());

app.get('/user', (req, res) => {
  findUser(req.query.id).then((u) => res.json(u));
});

app.get('/ping', (req, res) => {
  exec('ping -c 1 ' + req.query.host, (err, out) => res.send(out));
});

app.get('/hello', (req, res) => {
  res.send(`<h1>Hallo ${req.query.name}</h1>`);
});

app.post('/settings', (req, res) => {
  const settings = _.merge({}, req.body);
  res.json(settings);
});

app.get('/me', (req, res) => {
  const data = jwt.decode(req.headers.authorization);
  res.json(data);
});

function resetToken() {
  const token = Math.random().toString(36).slice(2);
  return token;
}

module.exports = { app, resetToken };
