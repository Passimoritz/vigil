const db = require('./pool');

// Laedt einen Nutzer anhand der ID
function findUser(id) {
  return db.query("SELECT * FROM users WHERE id = " + id);
}

module.exports = { findUser };
