/**
 * index.js — Special Perm Bot (Railway-ready) + Logs + Audit Monitoring + Roblox Kill Logs
 *
 * REQUIRED Railway Variables (or local .env):
 *   DISCORD_TOKEN
 *   CLIENT_ID
 *   GUILD_ID
 *
 * NEW Railway Variables for Roblox kill logs:
 *   KILL_LOG_CHANNEL_ID
 *   KILL_LOG_SECRET
 *
 * IMPORTANT:
 * - Railway gives PORT automatically; we must listen on it for public domain.
 * - Slash commands must be registered with deploy-commands.js at least once.
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
   CONFIG (YOUR IDS)
========================= */
const CONFIG = {
  AUTHCODEGEN_ROLE_IDS: ["1385085079809687714", "1428945562782404718"],
  SPECIAL_ROLE_ID: "1456387188517372018",
  SERVERPERMS_ALLOWED_ROLE_IDS: ["1456390190951305267"],

  AUTH_LOG_CHANNEL_ID: "1456391810074018023",
  PERM_LOG_CHANNEL_ID: "1456391918383661382",
  SPECIAL_ACTIVITY_LOG_CHANNEL_ID: "1456391963560382647",

  // Roblox kill logs
  KILL_LOG_CHANNEL_ID: process.env.KILL_LOG_CHANNEL_ID || "", // set in Railway Variables
  KILL_LOG_SECRET: process.env.KILL_LOG_SECRET || "", // set in Railway Variables

  AUTHCODE_TTL_MS: 60_000,          // 1 minute
  EXPIRY_CHECK_INTERVAL_MS: 10_000, // role expiry check
  AUDIT_POLL_INTERVAL_MS: 3000,     // audit polling

  EMBED_COLOR: 0xe53935,
};

/* =========================
   CRASH LOGS
========================= */
process.on("unhandledRejection", (e) => console.error("UNHANDLED REJECTION:", e));
process.on("uncaughtException", (e) => console.error("UNCAUGHT EXCEPTION:", e));

/* =========================
   STORAGE (JSON)
   NOTE: Railway filesystem can reset on redeploy.
========================= */
const DATA_DIR = path.join(__dirname, "data");
const AUTH_FILE = path.join(DATA_DIR, "authcodes.json");
const GRANTS_FILE = path.join(DATA_DIR, "grants.json");
const STATE_FILE = path.join(DATA_DIR, "state.json");

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
   TIME PARSING
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
   ROLE CHECK
========================= */
function memberHasAnyRole(member, roleIds) {
  return roleIds.some((id) => member.roles.cache.has(id));
}

/* =========================
   AUTH CODES
========================= */
function createAuthCode(createdBy, reason) {
  const db = readJson(AUTH_FILE);
  const code = crypto.randomBytes(10).toString("base64url");
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
   GRANTS (SPECIAL ROLE TIMER)
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

function buildCardEmbed({ title, invokerUser, dateMs, lengthText, reason, authcode, targetUserId }) {
  const e = new EmbedBuilder()
    .setColor(CONFIG.EMBED_COLOR)
    .setTitle(title)
    .setTimestamp(new Date(dateMs || now()));

  if (invokerUser?.displayAvatarURL) {
    e.setThumbnail(invokerUser.displayAvatarURL({ size: 256 }));
  }

  const fields = [
    { name: "Date", value: `<t:${Math.floor((dateMs || now()) / 1000)}:f>`, inline: true },
    { name: "Length", value: lengthText || "—", inline: true },
    { name: "Reason", value: reason, inline: false },
  ];

  if (authcode) fields.push({ name: "Authorization Code", value: `\`${authcode}\``, inline: false });
  if (targetUserId) fields.push({ name: "User ID", value: `${targetUserId}`, inline: false });

  e.addFields(fields);
  return e;
}

/* =========================
   SPECIAL CHECK (role OR timer)
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
  if (!expired.length) return;

  const guild = await client.guilds.fetch(process.env.GUILD_ID).catch(() => null);
  if (!guild) return;

  for (const userId of expired) {
    const member = await guild.members.fetch(userId).catch(() => null);
    if (member) await member.roles.remove(CONFIG.SPECIAL_ROLE_ID, "Temporary permissions expired").catch(() => {});
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
   AUDIT POLLING (for actions)
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

  await sendEmbed(guild, CONFIG.SPECIAL_ACTIVITY_LOG_CHANNEL_ID, embed);
}

async function pollAuditLogs() {
  const guild = await client.guilds.fetch(process.env.GUILD_ID).catch(() => null);
  if (!guild) return;

  const logs = await guild.fetchAuditLogs({ limit: 10 }).catch(() => null);
  if (!logs) return;

  const entries = [...logs.entries.values()]; // newest first
  if (!entries.length) return;

  const state = readJson(STATE_FILE);
  const lastId = state.lastAuditId;

  if (!lastId) {
    state.lastAuditId = entries[0].id;
    writeJson(STATE_FILE, state);
    return;
  }

  const newOnes = [];
  for (const e of entries) {
    if (e.id === lastId) break;
    newOnes.push(e);
  }
  if (!newOnes.length) return;

  state.lastAuditId = entries[0].id;
  writeJson(STATE_FILE, state);

  newOnes.reverse(); // oldest -> newest
  for (const entry of newOnes) {
    await logAuditEntryIfSpecial(guild, entry);
  }
}

/* =========================
   MORE EVENTS (fast, real-time)
========================= */

// messages
client.on("messageCreate", async (message) => {
  if (!message.guild || message.author.bot) return;
  const special = await isSpecialMember(message.guild, message.author.id);
  if (!special) return;

  const content = message.content?.length ? message.content : "(no text)";
  const attach = message.attachments?.size
    ? `\n\nAttachments:\n${[...message.attachments.values()].map((a) => a.url).join("\n")}`
    : "";

  const embed = new EmbedBuilder()
    .setColor(CONFIG.EMBED_COLOR)
    .setTitle("Message sent (special user)")
    .setDescription(
      `User: <@${message.author.id}> (${message.author.id})\n` +
        `Channel: <#${message.channel.id}>\n\n` +
        `**Content:**\n${content.slice(0, 1500)}${content.length > 1500 ? "…" : ""}` +
        attach
    )
    .setTimestamp(new Date());

  await sendEmbed(message.guild, CONFIG.SPECIAL_ACTIVITY_LOG_CHANNEL_ID, embed);
});

client.on("messageUpdate", async (oldMsg, newMsg) => {
  if (!newMsg.guild || !newMsg.author || newMsg.author.bot) return;
  const special = await isSpecialMember(newMsg.guild, newMsg.author.id);
  if (!special) return;

  const before = oldMsg?.content ?? "(uncached)";
  const after = newMsg?.content ?? "(empty)";
  if (before === after) return;

  const embed = new EmbedBuilder()
    .setColor(CONFIG.EMBED_COLOR)
    .setTitle("Message edited (special user)")
    .setDescription(
      `User: <@${newMsg.author.id}> (${newMsg.author.id})\n` +
        `Channel: <#${newMsg.channel.id}>\n\n` +
        `**Before:**\n${String(before).slice(0, 900)}\n\n` +
        `**After:**\n${String(after).slice(0, 900)}`
    )
    .setTimestamp(new Date());

  await sendEmbed(newMsg.guild, CONFIG.SPECIAL_ACTIVITY_LOG_CHANNEL_ID, embed);
});

client.on("messageDelete", async (message) => {
  if (!message.guild || !message.author || message.author.bot) return;
  const special = await isSpecialMember(message.guild, message.author.id);
  if (!special) return;

  const content = message.content?.length ? message.content : "(no text)";
  const embed = new EmbedBuilder()
    .setColor(CONFIG.EMBED_COLOR)
    .setTitle("Message deleted (special user)")
    .setDescription(
      `User: <@${message.author.id}> (${message.author.id})\n` +
        `Channel: <#${message.channel.id}>\n\n` +
        `**Content:**\n${content.slice(0, 1500)}`
    )
    .setTimestamp(new Date());

  await sendEmbed(message.guild, CONFIG.SPECIAL_ACTIVITY_LOG_CHANNEL_ID, embed);
});

// nickname changes
client.on("guildMemberUpdate", async (oldMember, newMember) => {
  if (oldMember.nickname === newMember.nickname) return;

  const special = await isSpecialMember(newMember.guild, newMember.id);
  if (!special) return;

  const embed = new EmbedBuilder()
    .setColor(CONFIG.EMBED_COLOR)
    .setTitle("Nickname changed (special user)")
    .setDescription(
      `User: <@${newMember.id}> (${newMember.id})\n` +
        `Old: **${oldMember.nickname || "None"}**\n` +
        `New: **${newMember.nickname || "None"}**`
    )
    .setTimestamp(new Date());

  await sendEmbed(newMember.guild, CONFIG.SPECIAL_ACTIVITY_LOG_CHANNEL_ID, embed);
});

// voice join/leave/move
client.on("voiceStateUpdate", async (oldState, newState) => {
  const guild = newState.guild;
  const member = newState.member;
  if (!guild || !member) return;

  const special = await isSpecialMember(guild, member.id);
  if (!special) return;

  const changes = [];

  if (!oldState.channel && newState.channel) changes.push(`Joined **${newState.channel.name}**`);
  else if (oldState.channel && !newState.channel) changes.push(`Left **${oldState.channel.name}**`);
  else if (oldState.channelId !== newState.channelId)
    changes.push(`Moved **${oldState.channel?.name}** → **${newState.channel?.name}**`);

  if (oldState.selfMute !== newState.selfMute) changes.push(`Self mute: **${newState.selfMute ? "ON" : "OFF"}**`);
  if (oldState.selfDeaf !== newState.selfDeaf) changes.push(`Self deaf: **${newState.selfDeaf ? "ON" : "OFF"}**`);

  if (!changes.length) return;

  const embed = new EmbedBuilder()
    .setColor(CONFIG.EMBED_COLOR)
    .setTitle("Voice activity (special user)")
    .setDescription(`User: <@${member.id}> (${member.id})\n\n${changes.map((x) => `• ${x}`).join("\n")}`)
    .setTimestamp(new Date());

  await sendEmbed(guild, CONFIG.SPECIAL_ACTIVITY_LOG_CHANNEL_ID, embed);
});

// role permission diffs
client.on("roleUpdate", async (oldRole, newRole) => {
  const changes = [];
  if (oldRole.name !== newRole.name) changes.push(`Name: **${oldRole.name}** → **${newRole.name}**`);

  const oldSet = new Set(new PermissionsBitField(oldRole.permissions).toArray());
  const newSet = new Set(new PermissionsBitField(newRole.permissions).toArray());
  const added = [...newSet].filter((p) => !oldSet.has(p));
  const removed = [...oldSet].filter((p) => !newSet.has(p));

  if (added.length) changes.push(`Permissions added:\n${added.map((p) => `• ${p}`).join("\n")}`);
  if (removed.length) changes.push(`Permissions removed:\n${removed.map((p) => `• ${p}`).join("\n")}`);

  if (!changes.length) return;

  const embed = new EmbedBuilder()
    .setColor(CONFIG.EMBED_COLOR)
    .setTitle("Role updated (permission diff)")
    .setDescription(`Role: **${newRole.name}** (${newRole.id})\n\n${changes.join("\n\n")}`)
    .setTimestamp(new Date());

  await sendEmbed(newRole.guild, CONFIG.SPECIAL_ACTIVITY_LOG_CHANNEL_ID, embed);
});

/* =========================
   ROBLOX KILL LOG HELPERS
========================= */
function robloxProfileUrl(userId) {
  return `https://www.roblox.com/users/${userId}/profile`;
}

// This one is a direct image URL (works as Discord thumbnail)
function robloxHeadshotImageUrl(userId) {
  return `https://www.roblox.com/headshot-thumbnail/image?userId=${userId}&width=150&height=150&format=png`;
}

function buildRobloxKillEmbed({ victimName, victimUserId, killerName, killerUserId, timeMs }) {
  const victimLink = robloxProfileUrl(victimUserId);
  const killerLink = robloxProfileUrl(killerUserId);

  const killedBlock =
    `Killed User (Unarmed)\n` +
    `[${victimName}](${victimLink}) [Target]`;

  const killerBlock =
    `[${killerName}](${killerLink}) [Citizen]`;

  return new EmbedBuilder()
    .setColor(0xe53935) // RED like you asked
    .setTitle("Los Santos Kill Logs")
    .setURL(victimLink) // clicking title opens victim profile
    .setThumbnail(robloxHeadshotImageUrl(victimUserId))
    .addFields(
      { name: "Game", value: killedBlock, inline: false },
      { name: "Killer", value: killerBlock, inline: false },
      { name: "Time", value: `<t:${Math.floor((timeMs || Date.now()) / 1000)}:F>`, inline: false }
    )
    .setFooter({ text: `Roblox ID: ${victimUserId}` })
    .setTimestamp(new Date(timeMs || Date.now()));
}

/* =========================
   RAILWAY HEALTH SERVER + ROBLOX ENDPOINT
   (single server only)
========================= */
const PORT = process.env.PORT || 3000;

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", (chunk) => (data += chunk));
    req.on("end", () => resolve(data));
    req.on("error", reject);
  });
}

const webServer = http.createServer(async (req, res) => {
  // health check
  if (req.method === "GET" && req.url === "/health") {
    res.writeHead(200, { "Content-Type": "text/plain" });
    return res.end("OK");
  }

  // roblox kill logs
  if (req.method === "POST" && req.url === "/roblox/kill") {
    try {
      if (!CONFIG.KILL_LOG_CHANNEL_ID || !CONFIG.KILL_LOG_SECRET) {
        res.writeHead(500, { "Content-Type": "text/plain" });
        return res.end("Kill log not configured");
      }

      const secret = req.headers["x-killlog-secret"];
      if (secret !== CONFIG.KILL_LOG_SECRET) {
        res.writeHead(401, { "Content-Type": "text/plain" });
        return res.end("Unauthorized");
      }

      if (!client.isReady()) {
        res.writeHead(503, { "Content-Type": "text/plain" });
        return res.end("Bot not ready");
      }

      const raw = await readBody(req);
      const body = JSON.parse(raw || "{}");

      const victimName = String(body.victimName || "").trim();
      const victimUserId = String(body.victimUserId || "").trim();
      const killerName = String(body.killerName || "").trim();
      const killerUserId = String(body.killerUserId || "").trim();
      const timeMs = typeof body.timeMs === "number" ? body.timeMs : Date.now();

      if (!victimName || !victimUserId || !killerName || !killerUserId) {
        res.writeHead(400, { "Content-Type": "text/plain" });
        return res.end("Missing fields");
      }

      const guild = await client.guilds.fetch(process.env.GUILD_ID);
      const channel = await guild.channels.fetch(CONFIG.KILL_LOG_CHANNEL_ID);

      const embed = buildRobloxKillEmbed({
        victimName,
        victimUserId,
        killerName,
        killerUserId,
        timeMs,
      });

      await channel.send({ embeds: [embed] });

      res.writeHead(200, { "Content-Type": "text/plain" });
      return res.end("Logged");
    } catch (e) {
      console.error("Roblox kill log endpoint error:", e);
      res.writeHead(500, { "Content-Type": "text/plain" });
      return res.end("Server error");
    }
  }

  res.writeHead(404, { "Content-Type": "text/plain" });
  res.end("Not found");
});

webServer.listen(PORT, "0.0.0.0", () => {
  console.log(`✅ Listening on port ${PORT}`);
});
webServer.on("error", (err) => console.error("❌ HTTP server error:", err));

console.log("✅ index.js started");

/* =========================
   SLASH COMMAND HANDLER
   (deferReply prevents "did not respond")
========================= */
client.on("interactionCreate", async (interaction) => {
  if (!interaction.isChatInputCommand()) return;
  if (!interaction.guild) return;

  try {
    await interaction.deferReply({ ephemeral: true });

    const guild = interaction.guild;
    const invoker = await guild.members.fetch(interaction.user.id);

    // /authcodegen reason
    if (interaction.commandName === "authcodegen") {
      if (!memberHasAnyRole(invoker, CONFIG.AUTHCODEGEN_ROLE_IDS)) {
        return interaction.editReply("❌ You don’t have permission to generate auth codes.");
      }

      const reason = interaction.options.getString("reason", true).trim();
      const code = createAuthCode(interaction.user.id, reason);
      const expiresAt = now() + CONFIG.AUTHCODE_TTL_MS;

      await interaction.editReply(
        `✅ Auth code (expires <t:${Math.floor(expiresAt / 1000)}:R>):\n\`${code}\``
      );

      const embed = buildCardEmbed({
        title: `Auth code generated by ${interaction.user.username}`,
        invokerUser: interaction.user,
        dateMs: now(),
        lengthText: "1 minute",
        reason,
        authcode: code,
      });

      await sendEmbed(guild, CONFIG.AUTH_LOG_CHANNEL_ID, embed);
      return;
    }

    // /serverpermissions userid authcode reason time
    if (interaction.commandName === "serverpermissions") {
      if (!memberHasAnyRole(invoker, CONFIG.SERVERPERMS_ALLOWED_ROLE_IDS)) {
        return interaction.editReply("❌ You don’t have permission to grant/revoke.");
      }

      const userId = interaction.options.getString("userid", true).trim();
      const authcode = interaction.options.getString("authcode", true).trim();
      const reason = interaction.options.getString("reason", true).trim();
      const timeStr = interaction.options.getString("time", true).trim();

      if (!/^\d{15,25}$/.test(userId)) {
        return interaction.editReply("❌ Invalid userid. Must be a Discord user ID.");
      }

      const durationMs = parseDuration(timeStr);
      if (!durationMs) {
        return interaction.editReply("❌ Invalid time format. Use 10s, 10m, 2h, 4d.");
      }

      const consumed = consumeAuthCode(authcode, userId);
      if (!consumed.ok) {
        return interaction.editReply(`❌ Auth code rejected: ${consumed.reason}`);
      }

      const targetMember = await guild.members.fetch(userId).catch(() => null);
      if (!targetMember) {
        return interaction.editReply("❌ That user is not in this server (or I can’t fetch them).");
      }

      await targetMember.roles.add(CONFIG.SPECIAL_ROLE_ID, reason);

      const expiresAt = now() + durationMs;
      setGrant(userId, interaction.user.id, expiresAt, reason, authcode);

      await interaction.editReply(
        `✅ Granted special role to <@${userId}> for **${prettyDuration(timeStr)}**.\nExpires: <t:${Math.floor(
          expiresAt / 1000
        )}:R>`
      );

      const embed = buildCardEmbed({
        title: `Permissions granted by ${interaction.user.username}`,
        invokerUser: interaction.user,
        dateMs: now(),
        lengthText: prettyDuration(timeStr),
        reason,
        authcode,
        targetUserId: userId,
      });

      await sendEmbed(guild, CONFIG.PERM_LOG_CHANNEL_ID, embed);
      return;
    }

    // /revokepermissions userid reason
    if (interaction.commandName === "revokepermissions") {
      if (!memberHasAnyRole(invoker, CONFIG.SERVERPERMS_ALLOWED_ROLE_IDS)) {
        return interaction.editReply("❌ You don’t have permission to grant/revoke.");
      }

      const userId = interaction.options.getString("userid", true).trim();
      const reason = interaction.options.getString("reason", true).trim();

      if (!/^\d{15,25}$/.test(userId)) {
        return interaction.editReply("❌ Invalid userid. Must be a Discord user ID.");
      }

      const targetMember = await guild.members.fetch(userId).catch(() => null);
      if (targetMember) {
        await targetMember.roles.remove(CONFIG.SPECIAL_ROLE_ID, reason).catch(() => {});
      }

      removeGrant(userId);

      await interaction.editReply(`✅ Revoked special role from <@${userId}>.`);

      const embed = buildCardEmbed({
        title: `Permissions revoked by ${interaction.user.username}`,
        invokerUser: interaction.user,
        dateMs: now(),
        lengthText: "—",
        reason,
        authcode: "—",
        targetUserId: userId,
      });

      await sendEmbed(guild, CONFIG.PERM_LOG_CHANNEL_ID, embed);
      return;
    }

    await interaction.editReply("❌ Unknown command.");

  } catch (err) {
    console.error("Slash command error:", err);
    if (interaction.deferred || interaction.replied) {
      await interaction.editReply("❌ Error running that command. Check Railway logs.");
    } else {
      await interaction.reply({ content: "❌ Error running that command. Check Railway logs.", ephemeral: true });
    }
  }
});

/* =========================
   READY
========================= */
client.once("ready", async () => {
  console.log(`✅ Logged in as ${client.user.tag}`);

  await enforceExpirations();
  setInterval(enforceExpirations, CONFIG.EXPIRY_CHECK_INTERVAL_MS);
  setInterval(pollAuditLogs, CONFIG.AUDIT_POLL_INTERVAL_MS);
});

/* =========================
   LOGIN (with loud debug)
========================= */
console.log("DEBUG env set:", {
  DISCORD_TOKEN: !!process.env.DISCORD_TOKEN,
  CLIENT_ID: !!process.env.CLIENT_ID,
  GUILD_ID: !!process.env.GUILD_ID,
  KILL_LOG_CHANNEL_ID: !!process.env.KILL_LOG_CHANNEL_ID,
  KILL_LOG_SECRET: !!process.env.KILL_LOG_SECRET,
});

if (!process.env.DISCORD_TOKEN) {
  console.error("❌ DISCORD_TOKEN missing in Railway Variables.");
} else {
  client
    .login(process.env.DISCORD_TOKEN)
    .then(() => console.log("✅ client.login() resolved"))
    .catch((e) => console.error("❌ Discord login failed:", e));
}
