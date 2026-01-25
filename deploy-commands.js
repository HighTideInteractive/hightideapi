require("dotenv").config();
const { REST, Routes, SlashCommandBuilder } = require("discord.js");

const token = process.env.DISCORD_TOKEN;
const clientId = process.env.CLIENT_ID;
const guildId = process.env.GUILD_ID;

if (!token || !clientId || !guildId) {
  console.error("Missing DISCORD_TOKEN / CLIENT_ID / GUILD_ID in .env or Railway Variables");
  process.exit(1);
}

const commands = [
  new SlashCommandBuilder()
    .setName("authcodegen")
    .setDescription("Generate a 1-minute authorization code")
    .addStringOption((o) => o.setName("reason").setDescription("Reason").setRequired(true)),

  new SlashCommandBuilder()
    .setName("serverpermissions")
    .setDescription("Grant the special role to a user for a limited time")
    .addStringOption((o) => o.setName("userid").setDescription("User ID").setRequired(true))
    .addStringOption((o) => o.setName("authcode").setDescription("Authorization code").setRequired(true))
    .addStringOption((o) => o.setName("reason").setDescription("Reason").setRequired(true))
    .addStringOption((o) => o.setName("time").setDescription("Duration (10s, 10m, 2h, 4d)").setRequired(true)),

  new SlashCommandBuilder()
    .setName("revokepermissions")
    .setDescription("Revoke the special role from a user")
    .addStringOption((o) => o.setName("userid").setDescription("User ID").setRequired(true))
    .addStringOption((o) => o.setName("reason").setDescription("Reason").setRequired(true)),

  new SlashCommandBuilder()
    .setName("klogtest")
    .setDescription("Test Roblox kill log endpoint + posting to the kill log channels"),
].map((c) => c.toJSON());

const rest = new REST({ version: "10" }).setToken(token);

(async () => {
  try {
    console.log("Registering slash commands...");
    await rest.put(Routes.applicationGuildCommands(clientId, guildId), { body: commands });
    console.log("✅ Slash commands registered.");
  } catch (err) {
    console.error(err);
  }
})();
