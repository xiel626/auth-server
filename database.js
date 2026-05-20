/**
 * Banco de dados do sistema Auth OAuth2
 * Separado do banco de tickets/keys para não haver conflito
 */
const { JsonDatabase } = require("wio.db");
const path = require("path");
const fs   = require("fs");

const dbPath = path.join(__dirname, "..", "database");
if (!fs.existsSync(dbPath)) fs.mkdirSync(dbPath, { recursive: true });

const authConfig    = new JsonDatabase({ databasePath: path.join(dbPath, "auth_config.json") });
const authUsers     = new JsonDatabase({ databasePath: path.join(dbPath, "auth_users.json") });
const authMessage   = new JsonDatabase({ databasePath: path.join(dbPath, "auth_message.json") });
const authCarrinhos = new JsonDatabase({ databasePath: path.join(dbPath, "auth_carrinhos.json") });

module.exports = { authConfig, authUsers, authMessage, authCarrinhos };
