/**
 * index.js — Special Perms Bot (Railway-ready)
 *
 * ENV VARS (Railway Variables or local .env):
 *   DISCORD_TOKEN
 *   CLIENT_ID
 *   GUILD_ID
 *
 * NOTE:
 * - Railway requires listening on process.env.PORT for a public domain.
 * - Slash commands must be registered via deploy-commands.js (run locally once).
 */

require("dotenv").config();
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const http = require("http");

const {
  Client,
  GatewayIntentBits,
  Partials,
  EmbedBuilder,
  PermissionsBitField,
  AuditLogEvent,
} = require("discord.js");

/* =========================
   ✅ RAILWAY HTTP SERVER
========================= */
const PORT = process.env.PORT || 3000;

const server = http.createServer((req, res) => {
  if (req.url === "/health") {
    res.writeHead(200, { "Content-Type": "text/plain" });
    return res.end("OK");
  }
  res.writeHead(200, { "Content-Type": "text/plain" });
  res.end("Bot running");
});

server.listen(PORT, "0.0.0.0", () => {
  console.log("✅ Listening on port", PORT);
});
server.on("error", (err) => {
  console.error("❌ HTTP server error:", err);
});

console.log("✅ index.js started");

/* Crash visibility */
process.on("unhandledRejection", (e) => console.error("UNHANDLED REJECTION:", e));
process.on("uncaughtException", (e) => console.error("UNCAUGHT EXCEPTION:", e));

/* =========================
   CONFIG (YOUR IDS)
========================= */
const CONFIG = {
  AUTHCODEGEN_ROLE_IDS: ["1385085079809687714", "1428945562782404718"],
  SPECIAL_ROLE_ID: "1456387188517372018",
  SERVERPERMS_ALLOWED_ROLE_IDS: ["1456390190951305267"],

  AUTH_LOG_CHANNEL_ID: "1456391810074018023",
  PERM_LOG_CHANNEL_ID: "1456391918383661382",
  SPECIAL_ACTIVITY_LOG_CHANNEL_ID: "1456391963560382647",

  AUTHCODE_TTL_MS: 60_000,               // 1 minute
  EXPIRY_CHECK_INTERVAL_MS: 10_000,      // check role expiry every 10s
  AUDIT_POLL_INTERVAL_MS: 3000,          // poll audit logs every 3s

  EMBED_COLOR: 0xe53935,
};

/* =========================
   STORAGE FILES
========================= */
const DATA_DIR = path.join(__dirname, "data");
const AUTH_FILE = path.join(DATA_DIR, "authcodes.json");
const GRANTS_FILE = path.join(DATA_DIR, "grants.json");
const STATE_FILE = path.join(DATA_DIR, "state.json"); // stores lastAuditId

function ensureFiles() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR);
  if (!fs.existsSync(AUTH_FILE)) fs.writeFileSync(AUTH_FILE, JSON.stringify({ codes: {} }, null, 2));
  if (!fs.existsSync(GRANTS_FILE)) fs.writeFileSync(GRANTS_FILE, JSON.stringify({ grants: {} }, null, 2));
  if (!fs.existsSync(STATE_FILE)) fs.writeFileSync(STATE_FILE, JSON.stringify({ lastAuditId: null }, null, 2));
}
function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}
function writeJson(file, obj) {
  fs.writeFileSync(file, JSON.stringify(obj, null, 2));
}
function now() {
  return Date.now();
}
ensureFiles();

/* =========================
   TIME PARSE
========================= */
function parseDuration(input) {
  const m = /^(\d+)\s*([smhd])$/i.exec((input || "").trim());
  if (!m) return null;
  const value = parseInt(m[1], 10);
  const unit = m[2].toLowerCase();
  const mult = { s: 1000, m: 60_000, h: 3_600_000, d: 86_400_000 }[unit];
  if (!mult) return null;
  return value * mult;
}
function prettyDuration(input) {
  const m = /^(\d+)\s*([smhd])$/i.exec((input || "").trim());
  if (!m) return input;
  const n = parseInt(m[1], 10);
  const u = m[2].toLowerCase();
  const word = u === "s" ? "second" : u === "m" ? "minute" : u === "h" ? "hour" : "day";
  return `${n} ${word}${n === 1 ? "" : "s"}`;
}

/* =========================
   ROLE CHECKS
========================= */
function memberHasAnyRole(member, roleIds) {
  return roleIds.some((id) => member.roles.cache.has(id));
}

/* =========================
   AUTH CODES
========================= */
function createAuthCode(createdBy, reason) {
  const db = readJson(AUTH_FILE);
  const code = crypto.randomBytes(10).toString("base64url"); // short-ish, safe chars
  db.codes[code] = {
    createdBy,
    reason,
    createdAt: now(),
    expiresAt: now() + CONFIG.AUTHCODE_TTL_MS,
    used: false,
    usedAt: null,
    usedForUserId: null,
  };
  writeJson(AUTH_FILE, db);
  return code;
}

function consumeAuthCode(code, targetUserId) {
  const db = readJson(AUTH_FILE);
  const entry = db.codes[code];
  if (!entry) return { ok: false, reason: "Invalid code." };
  if (entry.used) return { ok: false, reason: "Code already used." };
  if (entry.expiresAt <= now()) return { ok: false, reason: "Code expired." };

  entry.used = true;
  entry.usedAt = now();
  entry.usedForUserId = targetUserId;
  writeJson(AUTH_FILE, db);
  return { ok: true, entry };
}

function cleanupExpiredAuthCodes() {
  const db = readJson(AUTH_FILE);
  const t = now();
  let changed = false;

  for (const [code, entry] of Object.entries(db.codes)) {
    if (!entry.used && entry.expiresAt <= t) {
      delete db.codes[code];
      changed = true;
    }
  }
  if (changed) writeJson(AUTH_FILE, db);
}

/* =========================
   GRANTS (WHO HAS SPECIAL ROLE + EXPIRY)
========================= */
function setGrant(userId, grantedBy, expiresAt, reason, authcode) {
  const db = readJson(GRANTS_FILE);
  db.grants[userId] = { grantedBy, grantedAt: now(), expiresAt, reason, authcode };
  writeJson(GRANTS_FILE, db);
}
function removeGrant(userId) {
  const db = readJson(GRANTS_FILE);
  delete db.grants[userId];
  writeJson(GRANTS_FILE, db);
}
function getGrant(userId) {
  const db = readJson(GRANTS_FILE);
  return db.grants[userId] || null;
}
function listExpiredGrants() {
  const db = readJson(GRANTS_FILE);
  const t = now();
  return Object.entries(db.grants)
    .filter(([, g]) => typeof g.expiresAt === "number" && g.expiresAt <= t)
    .map(([userId]) => userId);
}

/* =========================
   DISCORD CLIENT
========================= */
const client = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildMembers,

    GatewayIntentBits.GuildMessages,
    GatewayIntentBits.MessageContent,

    GatewayIntentBits.GuildVoiceStates,
  ],
  partials: [Partials.Channel, Partials.Message],
});

/* =========================
   LOG HELPERS
========================= */
async function fetchChannel(guild, id) {
  return guild.channels.fetch(id).catch(() => null);
}

async function sendEmbed(guild, channelId, embed) {
  const ch = await fetchChannel(guild, channelId);
  if (!ch) return;
  await ch.send({ embeds: [embed] }).catch((e) => console.error("Log send failed:", e));
}

/* Embed style similar to your screenshot */
function buildCardEmbed({
  title,
  invokerUser,
  dateMs,
  lengthText,
  reason,
  authcode,
  targetUserId,
}) {
  const e = new EmbedBuilder()
    .setColor(CONFIG.EMBED_COLOR)
    .setTitle(title)
    .setTimestamp(new Date(dateMs || now()));

  if (invokerUser?.displayAvatarURL) {
    e.setThumbnail(invokerUser.displayAvatarURL({ size: 256 }));
  }

  const fields = [];
  fields.push({ name: "Date", value: `<t:${Math.floor((dateMs || now()) / 1000)}:f>`, inline: true });
  if (lengthText) fields.push({ name: "Length", value: lengthText, inline: true });

  fields.push({ name: "Reason", value: reason || "(none)", inline: false });

  if (authcode) fields.push({ name: "Authorization Code", value: `\`${authcode}\``, inline: false });
  if (targetUserId) fields.push({ name: "User ID", value: `${targetUserId}`, inline: false });

  e.addFields(fields);
  return e;
}

/* =========================
   SPECIAL CHECK
========================= */
const specialCache = new Map(); // userId -> { val, at }

async function isSpecialMember(guild, userId) {
  const cached = specialCache.get(userId);
  if (cached && now() - cached.at < 15000) return cached.val;

  const g = getGrant(userId);
  const timerActive = !!(g && g.expiresAt > now());

  const member = await guild.members.fetch(userId).catch(() => null);
  const hasRole = !!member?.roles?.cache?.has(CONFIG.SPECIAL_ROLE_ID);

  const val = timerActive || hasRole;
  specialCache.set(userId, { val, at: now() });
  return val;
}

/* =========================
   EXPIRY ENFORCEMENT
========================= */
async function enforceExpirations() {
  cleanupExpiredAuthCodes();

  const expired = listExpiredGrants();
  if (expired.length === 0) return;

  const guild = await client.guilds.fetch(process.env.GUILD_ID).catch(() => null);
  if (!guild) return;

  for (const userId of expired) {
    const member = await guild.members.fetch(userId).catch(() => null);
    if (member) {
      await member.roles.remove(CONFIG.SPECIAL_ROLE_ID, "Temporary permissions expired").catch(() => {});
    }
    removeGrant(userId);

    const embed = new EmbedBuilder()
      .setColor(CONFIG.EMBED_COLOR)
      .setTitle("Role removed (expired)")
      .setDescription(`User: <@${userId}> (${userId})\nExpired automatically.`)
      .setTimestamp(new Date());

    await sendEmbed(guild, CONFIG.PERM_LOG_CHANNEL_ID, embed);
  }
}

/* =========================
   PERMISSION DIFF (ROLE UPDATE)
========================= */
function diffPermissions(oldPerms, newPerms) {
  const oldSet = new Set(new PermissionsBitField(oldPerms).toArray());
  const newSet = new Set(new PermissionsBitField(newPerms).toArray());
  const added = [...newSet].filter((p) => !oldSet.has(p));
  const removed = [...oldSet].filter((p) => !newSet.has(p));
  return { added, removed };
}

/* =========================
   AUDIT POLLER (catch actions)
========================= */
function actionName(actionId) {
  for (const [k, v] of Object.entries(AuditLogEvent)) {
    if (v === actionId) return k;
  }
  return `Action ${actionId}`;
}

async function logAuditEntryIfSpecial(guild, entry) {
  const executorId = entry.executorId;
  if (!executorId) return;

  const special = await isSpecialMember(guild, executorId);
  if (!special) return;

  const name = actionName(entry.action);
  const target = entry.target?.id
    ? `${entry.target?.name ?? entry.target?.username ?? "Target"} (${entry.target.id})`
    : "Unknown target";

  let changeText = "(no changes)";
  if (Array.isArray(entry.changes) && entry.changes.length) {
    changeText = entry.changes
      .slice(0, 12)
      .map((c) => `• \`${c.key}\`: ${JSON.stringify(c.old)} → ${JSON.stringify(c.new)}`)
      .join("\n");
  }

  const embed = new EmbedBuilder()
    .setColor(CONFIG.EMBED_COLOR)
    .setTitle("Admin action (special user)")
    .setDescription(
      `Executor: <@${executorId}> (${executorId})\n` +
      `Action: **${name}**\n` +
      `Target: ${target}\n` +
      (entry.reason ? `Reason: ${entry.reason}\n` : "") +
      `\n**Changes:**\n${changeText}`
    )
    .setTimestamp(new Date(entry.createdTimestamp || Date.now()));

  await sendEmbed(guild, CONFIG.S
