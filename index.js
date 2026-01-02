/**
 * index.js — High Tide API Bot
 * Fully fixed for Railway hosting
 */

require("dotenv").config();
const fs = require("fs");
const path = require("path");
const http = require("http");
const crypto = require("crypto");

const {
  Client,
  GatewayIntentBits,
  Partials,
  EmbedBuilder,
  AuditLogEvent,
  PermissionsBitField,
} = require("discord.js");

/* ===============================
   🚀 RAILWAY HTTP SERVER
================================ */
const PORT = process.env.PORT || 3000;

http.createServer((req, res) => {
  if (req.url === "/health") {
    res.writeHead(200, { "Content-Type": "text/plain" });
    return res.end("OK");
  }
  res.writeHead(200, { "Content-Type": "text/plain" });
  res.end("Bot running");
}).listen(PORT, "0.0.0.0", () => {
  console.log(`✅ Listening on port ${PORT}`);
});

console.log("✅ index.js started");

/* ===============================
   CONFIG
================================ */
const CONFIG = {
  AUTHCODEGEN_ROLE_IDS: ["1385085079809687714", "1428945562782404718"],
  SPECIAL_ROLE_ID: "1456387188517372018",
  SERVERPERMS_ALLOWED_ROLE_IDS: ["1456390190951305267"],

  AUTH_LOG_CHANNEL_ID: "1456391810074018023",
  PERM_LOG_CHANNEL_ID: "1456391918383661382",
  SPECIAL_ACTIVITY_LOG_CHANNEL_ID: "1456391963560382647",

  AUTHCODE_TTL_MS: 60_000,
  EXPIRY_CHECK_INTERVAL_MS: 10_000,
  AUDIT_POLL_INTERVAL_MS: 3000,

  EMBED_COLOR: 0xe53935,
};

/* ===============================
   FILE STORAGE
================================ */
const DATA_DIR = path.join(__dirname, "data");
const AUTH_FILE = path.join(DATA_DIR, "authcodes.json");
const GRANTS_FILE = path.join(DATA_DIR, "grants.json");
const STATE_FILE = path.join(DATA_DIR, "state.json");

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR);
if (!fs.existsSync(AUTH_FILE)) fs.writeFileSync(AUTH_FILE, JSON.stringify({ codes: {} }));
if (!fs.existsSync(GRANTS_FILE)) fs.writeFileSync(GRANTS_FILE, JSON.stringify({ grants: {} }));
if (!fs.existsSync(STATE_FILE)) fs.writeFileSync(STATE_FILE, JSON.stringify({ lastAuditId: null }));

const read = f => JSON.parse(fs.readFileSync(f));
const write = (f, d) => fs.writeFileSync(f, JSON.stringify(d, null, 2));

/* ===============================
   UTIL
================================ */
const now = () => Date.now();

function parseDuration(str) {
  const m = /^(\d+)([smhd])$/.exec(str);
  if (!m) return null;
  const mult = { s: 1000, m: 60000, h: 3600000, d: 86400000 };
  return parseInt(m[1]) * mult[m[2]];
}

function prettyDuration(str) {
  const m = /^(\d+)([smhd])$/.exec(str);
  if (!m) return str;
  const unit = { s: "second", m: "minute", h: "hour", d: "day" }[m[2]];
  return `${m[1]} ${unit}${m[1] === "1" ? "" : "s"}`;
}

/* ===============================
   DISCORD CLIENT
================================ */
const client = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildMembers,
    GatewayIntentBits.GuildMessages,
    GatewayIntentBits.MessageContent,
    GatewayIntentBits.GuildVoiceStates,
  ],
  partials: [Partials.Channel],
});

/* ===============================
   SAFE LOGGING
================================ */
function logEmbed(guild, channelId, embed) {
  guild.channels.fetch(channelId)
    .then(ch => ch?.send({ embeds: [embed] }))
    .catch(() => {});
}

/* ===============================
   AUTH CODE SYSTEM
================================ */
function createAuthCode(userId, reason) {
  const data = read(AUTH_FILE);
  const code = crypto.randomBytes(9).toString("hex");

  data.codes[code] = {
    createdBy: userId,
    createdAt: now(),
    expiresAt: now() + CONFIG.AUTHCODE_TTL_MS,
    used: false,
    reason
  };

  write(AUTH_FILE, data);
  return code;
}

function useAuthCode(code, target) {
  const data = read(AUTH_FILE);
  const entry = data.codes[code];
  if (!entry || entry.used || entry.expiresAt < now()) return false;

  entry.used = true;
  entry.usedFor = target;
  write(AUTH_FILE, data);
  return true;
}

/* ===============================
   BOT READY
================================ */
client.once("ready", () => {
  console.log(`✅ Logged in as ${client.user.tag}`);
});

/* ===============================
   LOGIN
================================ */
if (!process.env.DISCORD_TOKEN) {
  console.error("❌ DISCORD_TOKEN missing");
  process.exit(1);
}

client.login(process.env.DISCORD_TOKEN).catch(console.error);
