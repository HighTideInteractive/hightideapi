require("dotenv").config();
const { REST, Routes, SlashCommandBuilder } = require("discord.js");

const commands = [
  new SlashCommandBuilder()
    .setName("authcodegen")
    .setDescription("Generate a 1-minute one-time authorization code (restricted).")
    .addStringOption(opt =>
      opt.setName("reason")
        .setDescription("Reason (required)")
        .setRequired(true)
    ),

  new SlashCommandBuilder()
    .setName("serverpermissions")
    .setDescription("Grant temporary special permissions (requires auth code).")
    // EXACT order: userid, authcode, reason, time
    .addStringOption(opt =>
      opt.setName("userid")
        .setDescription("Discord User ID to receive the special role")
        .setRequired(true)
    )
    .addStringOption(opt =>
      opt.setName("authcode")
        .setDescription("Authorization code (expires after 1 minute)")
        .setRequired(true)
    )
    .addStringOption(opt =>
      opt.setName("reason")
        .setDescription("Reason (required)")
        .setRequired(true)
    )
    .addStringOption(opt =>
      opt.setName("time")
        .setDescription("Time: 10s, 10m, 2h, 4d")
        .setRequired(true)
    ),

  new SlashCommandBuilder()
    .setName("revokepermissions")
    .setDescription("Revoke the special role early.")
    .addStringOption(opt =>
      opt.setName("userid")
        .setDescription("Discord User ID to revoke the special role from")
        .setRequired(true)
    )
    .addStringOption(opt =>
      opt.setName("reason")
        .setDescription("Reason (required)")
        .setRequired(true)
    ),
].map(c => c.toJSON());

const rest = new REST({ version: "10" }).setToken(process.env.DISCORD_TOKEN);

(async () => {
  try {
    console.log("Registering slash commands...");
    await rest.put(
      Routes.applicationGuildCommands(process.env.CLIENT_ID, process.env.GUILD_ID),
      { body: commands }
    );
    console.log("Slash commands registered.");
  } catch (err) {
    console.error(err);
  }
})();
