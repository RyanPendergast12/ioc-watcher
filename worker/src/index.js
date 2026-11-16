/**
 * ioc-watcher Discord interaction endpoint (Cloudflare Worker).
 *
 * Discord → POST here when Approve / Deny / Edit is clicked.
 *  1. verify Ed25519 signature (DISCORD_PUBLIC_KEY)
 *  2. check the clicker is in ALLOWED_USER_IDS
 *  3. answer Discord immediately (it needs a reply within 3 s)
 *  4. fire GitHub repository_dispatch "ioc-decision" in the background
 *
 * Secrets / vars: DISCORD_PUBLIC_KEY, DISCORD_APPLICATION_ID, ALLOWED_USER_IDS (comma list),
 *                 GITHUB_TOKEN (fine-grained PAT: ioc-watcher → Contents read/write), GITHUB_REPO (owner/name)
 */

const PING = 1, COMPONENT = 3, MODAL_SUBMIT = 5;
const R_PONG = 1, R_MESSAGE = 4, R_UPDATE = 7, R_MODAL = 9;
const EPHEMERAL = 64;

export default {
  async fetch(request, env, ctx) {
    if (request.method !== "POST") return new Response("ioc-watcher interactions endpoint", { status: 200 });

    const sig = request.headers.get("X-Signature-Ed25519");
    const ts = request.headers.get("X-Signature-Timestamp");
    const body = await request.text();
    if (!sig || !ts || !(await verify(env.DISCORD_PUBLIC_KEY, sig, ts + body))) {
      return new Response("invalid request signature", { status: 401 });
    }

    const i = JSON.parse(body);
    if (i.type === PING) return json({ type: R_PONG });

    const user = i.member?.user ?? i.user ?? {};
    const allowed = (env.ALLOWED_USER_IDS || "").split(",").map((s) => s.trim()).filter(Boolean);
    if (!allowed.includes(user.id)) {
      return json({ type: R_MESSAGE, data: { content: "⛔ You're not on the ioc-watcher approver list.", flags: EPHEMERAL } });
    }

    const customId = i.data?.custom_id || "";
    const [action, pid] = customId.split(":");
    if (!/^[a-f0-9]{6,32}$/.test(pid || "")) {
      return json({ type: R_MESSAGE, data: { content: "Malformed proposal id.", flags: EPHEMERAL } });
    }

    if (i.type === COMPONENT && action === "edit") {
      return json({
        type: R_MODAL,
        data: {
          custom_id: `editsubmit:${pid}`,
          title: "Edit, then approve",
          components: [
            row(textInput("remove", "Remove — one IOC per line")),
            row(textInput("add", "Add — one IOC per line")),
          ],
        },
      });
    }

    let decision, remove = "", add = "";
    if (i.type === COMPONENT && (action === "approve" || action === "deny")) {
      decision = action;
    } else if (i.type === MODAL_SUBMIT && action === "editsubmit") {
      decision = "approve";
      for (const r of i.data.components || []) {
        for (const c of r.components || []) {
          if (c.custom_id === "remove") remove = c.value || "";
          if (c.custom_id === "add") add = c.value || "";
        }
      }
    } else {
      return json({ type: R_MESSAGE, data: { content: "Unknown action.", flags: EPHEMERAL } });
    }

    const payload = {
      proposal_id: pid,
      decision,
      user: user.global_name || user.username || "unknown",
      user_id: user.id,
      channel_id: i.channel_id || i.message?.channel_id,
      message_id: i.message?.id,
      remove: remove.slice(0, 4000),
      add: add.slice(0, 4000),
    };

    ctx.waitUntil(dispatch(env, payload, i));

    // Immediately swap the buttons for a "working" footer so it can't be double-clicked.
    const verb = decision === "approve" ? (remove || add ? "✏️ Edited + approved" : "✅ Approved") : "❌ Denied";
    const embeds = (i.message?.embeds || []).map((e) => ({
      ...e,
      color: 0x7f8c8d,
      footer: { text: `⏳ ${verb} by ${payload.user} — applying… · ${e.footer?.text || ""}`.slice(0, 2048) },
    }));
    return json({ type: R_UPDATE, data: { embeds, components: [] } });
  },
};

async function dispatch(env, payload, interaction) {
  const res = await fetch(`https://api.github.com/repos/${env.GITHUB_REPO}/dispatches`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${env.GITHUB_TOKEN}`,
      Accept: "application/vnd.github+json",
      "User-Agent": "ioc-watcher-worker",
      "X-GitHub-Api-Version": "2022-11-28",
    },
    body: JSON.stringify({ event_type: "ioc-decision", client_payload: payload }),
  });
  if (res.status !== 204) {
    // Put the buttons back and say why, so the click can be retried.
    const text = (await res.text()).slice(0, 300);
    await fetch(`https://discord.com/api/v10/webhooks/${env.DISCORD_APPLICATION_ID}/${interaction.token}/messages/@original`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        embeds: (interaction.message?.embeds || []).map((e) => ({
          ...e,
          footer: { text: `⚠️ GitHub dispatch failed (${res.status}): ${text}`.slice(0, 2048) },
        })),
        components: interaction.message?.components || [],
      }),
    });
  }
}

function row(component) {
  return { type: 1, components: [component] };
}

function textInput(id, label) {
  return { type: 4, custom_id: id, label, style: 2, required: false, max_length: 4000, placeholder: "evil-domain[.]com\n1.2.3.4\n<sha256>" };
}

function json(obj) {
  return new Response(JSON.stringify(obj), { headers: { "Content-Type": "application/json" } });
}

async function verify(publicKeyHex, sigHex, message) {
  try {
    const key = await crypto.subtle.importKey("raw", hex(publicKeyHex), { name: "Ed25519" }, false, ["verify"]);
    return await crypto.subtle.verify("Ed25519", key, hex(sigHex), new TextEncoder().encode(message));
  } catch {
    return false;
  }
}

function hex(s) {
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.substr(i * 2, 2), 16);
  return out;
}
