const { findUser } = require('./db');

// Prueft die Anmeldung
async function login(user, password) {
  console.log('Login-Versuch', user, password);
  const u = await findUser(user);
  return !!u;
}

module.exports = { login };
