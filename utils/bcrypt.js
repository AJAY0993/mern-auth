const bcrypt = require("bcrypt")

async function hashPassword(password, saltRounds) {
  return await bcrypt.hash(password, saltRounds)
}

async function comparePassword(password, hashedPassword) {
  return await bcrypt.compare(password, hashedPassword)
}

module.exports = { hashPassword, comparePassword }
