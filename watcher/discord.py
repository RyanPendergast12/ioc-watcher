"""Discord REST helpers (bot token). Messages are posted by the bot so they can carry buttons."""
from __future__ import annotations

import time
from collections import Counter

import requests

from . import iocs
from .common import env, repo_slug

API = "https://discord.com/api/v10"
COLORS = {"pending": 0xF5A524, "approve": 0x2ECC71, "deny": 0xE74C3C, "working": 0x7F8C8D, "error": 0xE67E22}
TYPE_LABEL = {"ip": "IP", "cidr": "CIDR", "domain": "Domain", "onion": "Onion", "sha256": "SHA256", "sha1": "SHA1", "md5": "MD5",
              "ssl_sha1": "SSL SHA1", "cve": "CVE", "report": "Report"}
ICON = {"iocs": "🚨", "bucket": "🗃️", "digest": "📰", "kev": "🛡️"}


def _headers():
    tok = env("DISCORD_BOT_TOKEN")
    if not tok:
        raise RuntimeError("DISCORD_BOT_TOKEN not set")
    return {"Authorization": f"Bot {tok}", "Content-Type": "application/json",
            "User-Agent": "DiscordBot (https://github.com/RyanPendergast12/ioc-watcher, 1.0)"}


def _req(method: str, path: str, payload: dict | None = None) -> dict:
    for _ in range(5):
        r = requests.request(method, API + path, headers=_headers(), json=payload, timeout=30)
        if r.status_code == 429:
            time.sleep(float(r.json().get("retry_after", 2)) + 0.25)
            continue
        if r.status_code >= 400:
            raise RuntimeError(f"Discord {method} {path} -> {r.status_code}: {r.text[:300]}")
        return r.json() if r.text else {}
    raise RuntimeError("Discord rate-limited repeatedly")


def _line(item: dict) -> str:
    t = item["type"]
    if t == "report":
        return f"📄 {item.get('title', '')[:70]} — {item.get('source', '')}"
    if t == "cve":
        flag = " ⚠️ransomware" if item.get("ransomware") else ""
        return f"{item['value']} {item.get('context', '')[:60]}{flag}"
    v = iocs.defang(item["value"], t)
    ctx = item.get("context", "")
    return f"{TYPE_LABEL.get(t, t):<6} {v}" + (f"  · {ctx[:40]}" if ctx else "")


def build_embed(p: dict, status: str = "pending", note: str = "") -> dict:
    items = p["items"]
    counts = Counter(TYPE_LABEL.get(i["type"], i["type"]) for i in items)
    sources = Counter(i.get("source", "?") for i in items)
    shown = items[:18]
    body = "\n".join(_line(i) for i in shown)
    if len(items) > len(shown):
        body += f"\n… +{len(items) - len(shown)} more"
    if p.get("overflow"):
        body += f"\n(+{p['overflow']} over the per-proposal cap were dropped)"
    link = f"https://github.com/{repo_slug()}/blob/main/{ {'approve': 'approved', 'deny': 'archive/denied'}.get(status, 'pending')}/{p['id']}.json"
    desc = f"**Target:** `{p['target_md']}`\n```\n{body[:3500]}\n```\n[Full proposal JSON]({link})"
    fields = [
        {"name": "Counts", "value": ", ".join(f"{v} {k}" for k, v in counts.items())[:1024] or "-", "inline": True},
        {"name": "Sources", "value": ", ".join(f"{k} ({v})" for k, v in sources.most_common(6))[:1024] or "-", "inline": True},
    ]
    if p.get("reports"):
        fields.append({"name": "Reporting", "value": "\n".join(f"[{r['title'][:80]}]({r['url']})" for r in p["reports"][:5])[:1024]})
    footer = f"proposal {p['id']} · {p['created'][:10]}"
    if note:
        footer = f"{note} · {footer}"
    return {"title": f"{ICON.get(p.get('kind'), '🚨')} {p['headline']}"[:256], "description": desc[:4096],
            "color": COLORS.get(status, COLORS["pending"]), "fields": fields, "footer": {"text": footer[:2048]}}


def buttons(pid: str) -> list[dict]:
    return [{"type": 1, "components": [
        {"type": 2, "style": 3, "label": "Approve", "emoji": {"name": "✅"}, "custom_id": f"approve:{pid}"},
        {"type": 2, "style": 4, "label": "Deny", "emoji": {"name": "❌"}, "custom_id": f"deny:{pid}"},
        {"type": 2, "style": 2, "label": "Edit", "emoji": {"name": "📝"}, "custom_id": f"edit:{pid}"},
    ]}]


def post_proposal(p: dict) -> dict:
    ch = env("DISCORD_CHANNEL_ID")
    if not ch:
        raise RuntimeError("DISCORD_CHANNEL_ID not set")
    msg = _req("POST", f"/channels/{ch}/messages", {"embeds": [build_embed(p)], "components": buttons(p["id"])})
    return {"channel_id": ch, "message_id": msg["id"]}


def update_message(channel_id: str, message_id: str, embed: dict, components: list | None = None) -> None:
    _req("PATCH", f"/channels/{channel_id}/messages/{message_id}", {"embeds": [embed], "components": components or []})


def post_text(content: str) -> None:
    ch = env("DISCORD_CHANNEL_ID")
    if ch and env("DISCORD_BOT_TOKEN"):
        _req("POST", f"/channels/{ch}/messages", {"content": content[:1990]})
