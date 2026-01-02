/**
 * index.js — Special Perms Bot + Audit Logging + Railway Health Endpoint
 *
 * REQUIRED ENV VARS (Railway Variables or local .env):
 *  - DISCORD_TOKEN
 *  - CLIENT_ID
 *  - GUILD_ID
 * Railway also provides PORT automatically.
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
  AuditLogEvent,
  PermissionsBitField,
} = require("discord.js");

/* =========================
   RAILWAY PUBLIC DOMAIN FIX
   (MUST RUN FIRST)
========================= */

const PORT = process.env.PORT || 3000;

http
  .createServer((req, res) => {
    if (req.url === "/health") {
      res.writeHead(200, { "Content-Type": "text/plain" });
      return res.end("OK");
    }
    res.writeHead(200, { "Content-Type": "text/plain" });
    return res.end("Bot running");
  })
  .listen(PORT, "0.0.0.0", () => {
    console.log("✅ Listening on port", PORT);
  });

console.log("✅ index.js started");

/* Log crashes clearly in Railway */
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

  AUTHCODE_TTL_MS: 60_000,
  EXPIRY_CHECK_INTERVAL_MS: 10_000,
  AUDIT_POLL_INTERVAL_MS: 3000,

  EMBED_COLOR: 0xe53935,
};

/* =========================
   STORAGE
========================= */
const DATA_DIR = path.join(__dirname, "data");
const AUTH_FILE = path.join(DATA_DIR, "authcodes.json");
const GRANTS_FILE = path.join(DATA_DIR, "grants.json");
const STATE_FILE = path.join(DATA_DIR, "state.json"); // last seen audit entry id

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
   AUTH CODES
========================= */
function createAuthCode(createdBy, reason) {
  const db = readJson(AUTH_FILE);
  const code = crypto.randomBytes(9).toString("base64url");
  db.codes[code] = {
    createdBy,
    createdAt: now(),
    expiresAt: now() + CONFIG.AUTHCODE_TTL_MS,
    used: false,
    usedAt: null,
    usedForUserId: null,
    reason,
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
    if (entry.expiresAt <= t && !entry.used) {
      delete db.codes[code];
      changed = true;
    }
  }
  if (changed) writeJson(AUTH_FILE, db);
}

/* =========================
   GRANTS
========================= */
function setGrant(userId, grantedBy, expiresAt, reason, authcode) {
  const db = readJson(GRANTS_FILE);
  db.grants[userId] = { expiresAt, grantedBy, grantedAt: now(), reason, authcode };
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
   CLIENT
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

function styledEmbed({ title, invokerUser, dateMs, lengthText, reason, authcode, targetUserId, extraLines }) {
  const avatar = invokerUser?.displayAvatarURL?.({ size: 256 }) || null;

  const e = new EmbedBuilder()
    .setColor(CONFIG.EMBED_COLOR)
    .setTitle(title)
    .setTimestamp(new Date(dateMs || now()));

  if (avatar) e.setThumbnail(avatar);
  if (extraLines) e.setDescription(extraLines);

  const fields = [];
  if (dateMs) fields.push({ name: "Date", value: `<t:${Math.floor(dateMs / 1000)}:f>`, inline: true });
  if (lengthText) fields.push({ name: "Length", value: lengthText, inline: true });
  if (reason) fields.push({ name: "Reason", value: reason, inline: false });
  if (authcode) fields.push({ name: "Authorization Code", value: `\`${authcode}\``, inline: false });
  if (targetUserId) fields.push({ name: "User ID", value: `${targetUserId}`, inline: false });

  if (fields.length) e.addFields(fields);
  return e;
}

function memberHasAnyRole(member, roleIds) {
  if (!Array.isArray(roleIds) || roleIds.length === 0) return false;
  return roleIds.some((id) => member.roles.cache.has(id));
}

/* =========================
   SPECIAL CHECK (ROLE OR TIMER) + CACHE
========================= */
const specialCache = new Map(); // userId -> { val, at }
async function isSpecialMember(guild, userId) {
  const cached = specialCache.get(userId);
  if (cached && now() - cached.at < 15_000) return cached.val;

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
   ROLE PERMISSION DIFF
========================= */
function diffPermissions(oldPerms, newPerms) {
  const oldSet = new Set(new PermissionsBitField(oldPerms).toArray());
  const newSet = new Set(new PermissionsBitField(newPerms).toArray());
  const added = [...newSet].filter((p) => !oldSet.has(p));
  const removed = [...oldSet].filter((p) => !newSet.has(p));
  return { added, removed };
}

/* =========================
   AUDIT: LIVE + POLLING FALLBACK
========================= */
function actionNameFromId(actionId) {
  return Object.keys(AuditLogEvent).find((k) => AuditLogEvent[k] === actionId) || `Action ${actionId}`;
}

async function logAuditEntryIfSpecial(guild, entry, sourceTag) {
  const executorId = entry.executorId;
  if (!executorId) return;

  const special = await isSpecialMember(guild, executorId);
  if (!special) return;

  const action = actionNameFromId(entry.action);

  const targetText =
    entry.target?.id
      ? `${entry.target?.name ?? entry.target?.username ?? "Target"} (${entry.target.id})`
      : "Unknown target";

  const changesPreview =
    Array.isArray(entry.changes) && entry.changes.length
      ? entry.changes
          .slice(0, 12)
          .map((c) => `• \`${c.key}\`: ${JSON.stringify(c.old)} → ${JSON.stringify(c.new)}`)
          .join("\n")
      : "(no changes provided)";

  const embed = new EmbedBuilder()
    .setColor(CONFIG.EMBED_COLOR)
    .setTitle(`Admin action logged (${sourceTag})`)
    .setDescription(
      `Executor: <@${executorId}> (${executorId})\n` +
        `Action: **${action}**\n` +
        `Target: ${targetText}\n` +
        (entry.reason ? `Reason: ${entry.reason}\n` : "") +
        `\n**Changes:**\n${changesPreview}`
    )
    .setTimestamp(new Date(entry.createdTimestamp || Date.now()));

  await sendEmbed(guild, CONFIG.SPECIAL_ACTIVITY_LOG_CHANNEL_ID, embed);
}

client.on("guildAuditLogEntryCreate", async (entry, guild) => {
  try {
    await logAuditEntryIfSpecial(guild, entry, "live");
  } catch (e) {
    console.error("guildAuditLogEntryCreate error:", e);
  }
});

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

  newOnes.reverse();
  for (const entry of newOnes) {
    await logAuditEntryIfSpecial(guild, entry, "polled");
  }
}

/* =========================
   READY
========================= */
client.once("ready", async () => {
  console.log(`✅ Discord logged in as ${client.user.tag}`);

  await enforceExpirations();
  setInterval(enforceExpirations, CONFIG.EXPIRY_CHECK_INTERVAL_MS);
  setInterval(pollAuditLogs, CONFIG.AUDIT_POLL_INTERVAL_MS);
});

/* =========================
   COMMANDS
========================= */
client.on("interactionCreate", async (interaction) => {
  if (!interaction.isChatInputCommand()) return;
  const guild = interaction.guild;
  if (!guild) return interaction.reply({ content: "Use this in a server.", ephemeral: true });

  const invokerMember = await guild.members.fetch(interaction.user.id).catch(() => null);
  if (!invokerMember) return interaction.reply({ content: "Could not fetch your member info.", ephemeral: true });

  if (interaction.commandName === "authcodegen") {
    if (!memberHasAnyRole(invokerMember, CONFIG.AUTHCODEGEN_ROLE_IDS)) {
      return interaction.reply({ content: "You don’t have permission to generate auth codes.", ephemeral: true });
    }

    const reason = interaction.options.getString("reason", true).trim();
    const code = createAuthCode(interaction.user.id, reason);
    const expiresAt = now() + CONFIG.AUTHCODE_TTL_MS;

    await interaction.reply({
      content: `✅ Auth code (expires <t:${Math.floor(expiresAt / 1000)}:R>):\n\`${code}\``,
      ephemeral: true,
    });

    const embed = styledEmbed({
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

  if (interaction.commandName === "serverpermissions") {
    if (!memberHasAnyRole(invokerMember, CONFIG.SERVERPERMS_ALLOWED_ROLE_IDS)) {
      return interaction.reply({ content: "You don’t have permission to use this command.", ephemeral: true });
    }

    const userId = interaction.options.getString("userid", true).trim();
    const authcode = interaction.options.getString("authcode", true).trim();
    const reason = interaction.options.getString("reason", true).trim();
    const timeStr = interaction.options.getString("time", true).trim();

    if (!/^\d{15,25}$/.test(userId)) {
      return interaction.reply({ content: "Invalid userid. Must be a Discord user ID.", ephemeral: true });
    }

    const durationMs = parseDuration(timeStr);
    if (!durationMs || durationMs < 1000) {
      return interaction.reply({ content: "Invalid time. Use 10s, 10m, 2h, 4d.", ephemeral: true });
    }

    const consumed = consumeAuthCode(authcode, userId);
    if (!consumed.ok) {
      return interaction.reply({ content: `Auth code rejected: ${consumed.reason}`, ephemeral: true });
    }

    const targetMember = await guild.members.fetch(userId).catch(() => null);
    if (!targetMember) {
      return interaction.reply({ content: "That user is not in this server (or I can’t fetch them).", ephemeral: true });
    }

    await targetMember.roles
      .add(CONFIG.SPECIAL_ROLE_ID, reason)
      .catch(() =>
        interaction.reply({
          content: "I couldn’t add the role. Check Manage Roles + role hierarchy (bot role must be above the special role).",
          ephemeral: true,
        })
      );

    const expiresAt = now() + durationMs;
    setGrant(userId, interaction.user.id, expiresAt, reason, authcode);

    await interaction.reply({
      content: `✅ Granted special role to <@${userId}> for **${prettyDuration(timeStr)}**.\nExpires: <t:${Math.floor(expiresAt / 1000)}:R>`,
      ephemeral: true,
    });

    const embed = styledEmbed({
      title: `Permissions granted by ${interaction.user.username}`,
      invokerUser: interaction.user,
      dateMs: now(),
      lengthText: prettyDuration(timeStr),
      reason,
      authcode,
      targetUserId: userId,
      extraLines: `Target: <@${userId}>`,
    });

    await sendEmbed(guild, CONFIG.PERM_LOG_CHANNEL_ID, embed);
    return;
  }

  if (interaction.commandName === "revokepermissions") {
    if (!memberHasAnyRole(invokerMember, CONFIG.SERVERPERMS_ALLOWED_ROLE_IDS)) {
      return interaction.reply({ content: "You don’t have permission to use this command.", ephemeral: true });
    }

    const userId = interaction.options.getString("userid", true).trim();
    const reason = interaction.options.getString("reason", true).trim();

    if (!/^\d{15,25}$/.test(userId)) {
      return interaction.reply({ content: "Invalid userid. Must be a Discord user ID.", ephemeral: true });
    }

    const targetMember = await guild.members.fetch(userId).catch(() => null);
    if (targetMember) {
      await targetMember.roles.remove(CONFIG.SPECIAL_ROLE_ID, reason).catch(() => {});
    }

    removeGrant(userId);

    await interaction.reply({ content: `✅ Revoked special role from <@${userId}>.`, ephemeral: true });

    const embed = new EmbedBuilder()
      .setColor(CONFIG.EMBED_COLOR)
      .setTitle(`Permissions revoked by ${interaction.user.username}`)
      .setThumbnail(interaction.user.displayAvatarURL({ size: 256 }))
      .addFields(
        { name: "Date", value: `<t:${Math.floor(now() / 1000)}:f>`, inline: true },
        { name: "User ID", value: `${userId}`, inline: true },
        { name: "Reason", value: reason, inline: false }
      )
      .setDescription(`Target: <@${userId}>`)
      .setTimestamp(new Date());

    await sendEmbed(guild, CONFIG.PERM_LOG_CHANNEL_ID, embed);
    return;
  }
});

/* =========================
   SPECIAL USER ACTIVITY LOGS
========================= */
client.on("messageCreate", async (message) => {
  try {
    if (!message.guild) return;
    if (message.author.bot) return;

    const special = await isSpecialMember(message.guild, message.author.id);
    if (!special) return;

    const content = message.content?.length ? message.content : "(no text content)";
    const attachments = message.attachments?.size
      ? `\n\nAttachments:\n${[...message.attachments.values()].map((a) => a.url).join("\n")}`
      : "";

    const embed = new EmbedBuilder()
      .setColor(CONFIG.EMBED_COLOR)
      .setTitle("Message sent (special user)")
      .setDescription(
        `User: <@${message.author.id}> (${message.author.id})\n` +
          `Channel: <#${message.channel.id}>\n\n` +
          `**Content:**\n${content.slice(0, 1500)}${content.length > 1500 ? "…" : ""}` +
          attachments
      )
      .setTimestamp(new Date());

    await sendEmbed(message.guild, CONFIG.SPECIAL_ACTIVITY_LOG_CHANNEL_ID, embed);
  } catch (e) {
    console.error("messageCreate log error:", e);
  }
});

client.on("messageUpdate", async (oldMsg, newMsg) => {
  try {
    if (!newMsg.guild) return;
    if (!newMsg.author || newMsg.author.bot) return;

    const special = await isSpecialMember(newMsg.guild, newMsg.author.id);
    if (!special) return;

    const before = oldMsg?.content ?? "(unknown/uncached)";
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
  } catch (e) {
    console.error("messageUpdate log error:", e);
  }
});

client.on("messageDelete", async (message) => {
  try {
    if (!message.guild) return;
    if (!message.author || message.author.bot) return;

    const special = await isSpecialMember(message.guild, message.author.id);
    if (!special) return;

    const content = message.content?.length ? message.content : "(no text content)";

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
  } catch (e) {
    console.error("messageDelete log error:", e);
  }
});

/* Voice join/leave/move + mute/deafen toggles */
client.on("voiceStateUpdate", async (oldState, newState) => {
  try {
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
    if (oldState.serverMute !== newState.serverMute) changes.push(`Server mute: **${newState.serverMute ? "ON" : "OFF"}**`);
    if (oldState.serverDeaf !== newState.serverDeaf) changes.push(`Server deaf: **${newState.serverDeaf ? "ON" : "OFF"}**`);

    if (!changes.length) return;

    const embed = new EmbedBuilder()
      .setColor(CONFIG.EMBED_COLOR)
      .setTitle("Voice activity (special user)")
      .setDescription(`User: <@${member.id}> (${member.id})\n\n${changes.map((x) => `• ${x}`).join("\n")}`)
      .setTimestamp(new Date());

    await sendEmbed(guild, CONFIG.SPECIAL_ACTIVITY_LOG_CHANNEL_ID, embed);
  } catch (e) {
    console.error("voiceStateUpdate error:", e);
  }
});

/* Nickname changes for special users */
client.on("guildMemberUpdate", async (oldMember, newMember) => {
  try {
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
  } catch (e) {
    console.error("guildMemberUpdate(nickname) error:", e);
  }
});

/* Channel update visibility (executor comes via audit polling) */
client.on("channelUpdate", async (oldCh, newCh) => {
  try {
    const changes = [];
    if (oldCh.name !== newCh.name) changes.push(`Name: **${oldCh.name}** → **${newCh.name}**`);
    if ("topic" in oldCh && oldCh.topic !== newCh.topic) changes.push("Topic changed");
    if ("rateLimitPerUser" in oldCh && oldCh.rateLimitPerUser !== newCh.rateLimitPerUser) changes.push("Slowmode changed");
    if (!changes.length) return;

    const embed = new EmbedBuilder()
      .setColor(CONFIG.EMBED_COLOR)
      .setTitle("Channel updated")
      .setDescription(`Channel: <#${newCh.id}>\n\n${changes.map((x) => `• ${x}`).join("\n")}`)
      .setTimestamp(new Date());

    await sendEmbed(newCh.guild, CONFIG.SPECIAL_ACTIVITY_LOG_CHANNEL_ID, embed);
  } catch (e) {
    console.error("channelUpdate error:", e);
  }
});

/* Role permission diffs */
client.on("roleUpdate", async (oldRole, newRole) => {
  try {
    const changes = [];
    if (oldRole.name !== newRole.name) changes.push(`Name: **${oldRole.name}** → **${newRole.name}**`);

    const { added, removed } = diffPermissions(oldRole.permissions, newRole.permissions);
    if (added.length) changes.push(`Permissions added:\n${added.map((p) => `• ${p}`).join("\n")}`);
    if (removed.length) changes.push(`Permissions removed:\n${removed.map((p) => `• ${p}`).join("\n")}`);

    if (!changes.length) return;

    const embed = new EmbedBuilder()
      .setColor(CONFIG.EMBED_COLOR)
      .setTitle("Role updated (permissions diff)")
      .setDescription(`Role: **${newRole.name}** (${newRole.id})\n\n${changes.join("\n\n")}`)
      .setTimestamp(new Date());

    await sendEmbed(newRole.guild, CONFIG.SPECIAL_ACTIVITY_LOG_CHANNEL_ID, embed);
  } catch (e) {
    console.error("roleUpdate error:", e);
  }
});

/* Webhook updates: who did it will show via audit polling */
client.on("webhookUpdate", async (channel) => {
  try {
    const embed = new EmbedBuilder()
      .setColor(CONFIG.EMBED_COLOR)
      .setTitle("Webhook update detected")
      .setDescription(`Channel: <#${channel.id}> (see audit log entries for executor)`)
      .setTimestamp(new Date());

    await sendEmbed(channel.guild, CONFIG.SPECIAL_ACTIVITY_LOG_CHANNEL_ID, embed);
  } catch {}
});

/* =========================
   LOGIN
========================= */
if (!process.env.DISCORD_TOKEN) {
  console.error("❌ DISCORD_TOKEN missing. Set it in Railway Variables.");
} else {
  client.login(process.env.DISCORD_TOKEN).catch((e) => console.error("❌ Discord login failed:", e));
}
