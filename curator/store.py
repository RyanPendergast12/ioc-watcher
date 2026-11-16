"""Curator proposals: local store + Obsidian inbox note + Discord summary card + decision handling.

Content never leaves the laptop except as a short summary in Discord. Full diffs live in
<vault>/Curator Inbox/. The proposed page is an editable note: edit it in Obsidian before
approving and your edited version is what gets applied.
"""
from __future__ import annotations

import datetime as dt
import difflib
import os
import re
import uuid
from pathlib import Path

import requests

from .common import (PROPOSALS, cfg, frontmatter, load_json, log, save_json, sha, state, today,
                     vault_root)

ICON = {"writeup": "🧠", "new_page": "🆕", "coverage": "🧭", "hygiene": "🧹"}
LABEL = {"writeup": "Writeup refresh", "new_page": "New page", "coverage": "Coverage gaps", "hygiene": "Vault hygiene"}
API = "https://discord.com/api/v10"


def _inbox() -> Path:
    return vault_root() / cfg()["inbox_dir"]


def _note_paths(p: dict) -> tuple[Path, Path]:
    safe = re.sub(r'[\\/:*?"<>|#^\[\]]', "", p["title"])[:60]
    return (_inbox() / f"{p['id']} {LABEL[p['job']]} - {safe}.md", _inbox() / "proposed" / f"{p['id']}.md")


def safe_rel(rel: str) -> Path:
    v = vault_root().resolve()
    t = (v / rel).resolve()
    if v not in t.parents or t.suffix.lower() != ".md" or cfg()["inbox_dir"] in rel:
        raise ValueError(f"unsafe target {rel!r}")
    return t


# ------------------------------------------------------------------ create
def create(job: str, title: str, target_rel: str | None, new_content: str | None, summary: str,
           changes: list[str], edits: list[dict] | None = None, extra_md: str = "") -> dict:
    target = safe_rel(target_rel) if target_rel else None
    old = target.read_text(encoding="utf-8") if target and target.exists() else ""
    pid = uuid.uuid4().hex[:10]
    p = {"id": pid, "job": job, "title": title, "target_rel": target_rel, "created": dt.datetime.now().isoformat(timespec="seconds"),
         "base_sha256": sha(old) if target and target.exists() else None, "summary": summary, "changes": changes,
         "edits": edits or [], "status": "pending"}
    if new_content is not None:
        diff = list(difflib.unified_diff(old.splitlines(), new_content.splitlines(), "current", "proposed", lineterm="", n=2))
        p["stats"] = {"added": sum(1 for l in diff if l.startswith("+") and not l.startswith("+++")),
                      "removed": sum(1 for l in diff if l.startswith("-") and not l.startswith("---"))}
    else:
        diff, p["stats"] = [], {"added": 0, "removed": 0}
    note, proposed = _note_paths(p)
    note.parent.mkdir(parents=True, exist_ok=True)
    body = [f"---\ncurator_id: {pid}\njob: {job}\ntarget: \"[[{Path(target_rel).stem if target_rel else ''}]]\"\nstatus: pending\n---",
            f"# {ICON[job]} {LABEL[job]} — {title}", "",
            f"**Target:** `{target_rel or 'multiple files'}`  ", f"**Approve / deny:** Discord card `{pid}`", "",
            f"> {summary}", ""]
    if changes:
        body += ["## Changes", *[f"- {c}" for c in changes], ""]
    if new_content is not None:
        proposed.parent.mkdir(parents=True, exist_ok=True)
        proposed.write_text(new_content, encoding="utf-8")
        body += [f"## Proposed content", f"Full proposed page: [[{cfg()['inbox_dir']}/proposed/{pid}|proposed/{pid}]] — "
                 "**edit it before approving and your version is applied.**", "",
                 f"## Diff (+{p['stats']['added']} / −{p['stats']['removed']})", "```diff", *diff[:1500], "```"]
    if extra_md:
        body += ["", extra_md]
    note.write_text("\n".join(body) + "\n", encoding="utf-8")
    save_json(PROPOSALS / f"{pid}.json", p)
    return p


# ------------------------------------------------------------------ discord
def _hdr():
    return {"Authorization": f"Bot {os.environ['DISCORD_BOT_TOKEN']}", "Content-Type": "application/json",
            "User-Agent": "DiscordBot (ioc-watcher-curator, 1.0)"}


def _embed(p: dict, status: str = "pending", note: str = "") -> dict:
    color = {"pending": 0x9B59B6, "approve": 0x2ECC71, "deny": 0xE74C3C, "conflict": 0xE67E22}.get(status, 0x9B59B6)
    lines = [p["summary"][:600], ""] + [f"• {c[:150]}" for c in p["changes"][:6]]
    if p.get("stats", {}).get("added") or p.get("stats", {}).get("removed"):
        lines.append(f"\n`+{p['stats']['added']} / −{p['stats']['removed']} lines`")
    if p.get("edits"):
        lines.append(f"\n`{len(p['edits'])} edits`")
    lines.append(f"\n📓 Review in Obsidian → `{cfg()['inbox_dir']}`")
    footer = f"curator {p['id']} · {p['created'][:10]}"
    return {"title": f"{ICON[p['job']]} {LABEL[p['job']]} — {p['title']}"[:256], "description": "\n".join(lines)[:4000],
            "color": color, "footer": {"text": f"{note} · {footer}" if note else footer}}


def post(p: dict) -> None:
    ch = os.environ.get("DISCORD_CHANNEL_ID")
    if not (ch and os.environ.get("DISCORD_BOT_TOKEN")):
        log(f"{p['id']}: Discord not configured — review in Obsidian only")
        return
    comps = [{"type": 1, "components": [
        {"type": 2, "style": 3, "label": "Approve", "emoji": {"name": "✅"}, "custom_id": f"capprove:{p['id']}"},
        {"type": 2, "style": 4, "label": "Deny", "emoji": {"name": "❌"}, "custom_id": f"cdeny:{p['id']}"}]}]
    r = requests.post(f"{API}/channels/{ch}/messages", headers=_hdr(), json={"embeds": [_embed(p)], "components": comps}, timeout=30)
    if r.ok:
        p["discord"] = {"channel_id": ch, "message_id": r.json()["id"]}
        save_json(PROPOSALS / f"{p['id']}.json", p)
    else:
        log(f"{p['id']}: Discord post failed {r.status_code} {r.text[:200]}")


def _finish_card(p: dict, status: str, note: str) -> None:
    d = p.get("discord")
    if d and os.environ.get("DISCORD_BOT_TOKEN"):
        requests.patch(f"{API}/channels/{d['channel_id']}/messages/{d['message_id']}", headers=_hdr(),
                       json={"embeds": [_embed(p, status, note)], "components": []}, timeout=30)


# ------------------------------------------------------------------ decisions
def fetch_decisions() -> list[dict]:
    url, secret = os.environ.get("CURATOR_WORKER_URL"), os.environ.get("CURATOR_SECRET")
    if not (url and secret):
        return []
    r = requests.get(url.rstrip("/") + "/curator/decisions", headers={"Authorization": f"Bearer {secret}"}, timeout=20)
    r.raise_for_status()
    return r.json().get("decisions", [])


def ack(ids: list[str]) -> None:
    url, secret = os.environ.get("CURATOR_WORKER_URL"), os.environ.get("CURATOR_SECRET")
    if ids and url and secret:
        requests.post(url.rstrip("/") + "/curator/ack", headers={"Authorization": f"Bearer {secret}"},
                      json={"ids": ids}, timeout=20).raise_for_status()


def decide(pid: str, decision: str, user: str = "you") -> str:
    p = load_json(PROPOSALS / f"{pid}.json", None)
    if not p or p.get("status") != "pending":
        return "unknown or already decided"
    note, proposed = _note_paths(p)
    st = state()
    if decision == "deny":
        p["status"] = "denied"
        if p["job"] == "new_page":
            st["missing_done"].append(p["title"])
        result, card = f"❌ Denied by {user}", "deny"
    else:
        result, card = _apply(p, proposed, user)
    p["decided"] = {"by": user, "at": dt.datetime.now().isoformat(timespec="seconds"), "result": result}
    save_json(PROPOSALS / f"{pid}.json", p)
    for f in (note, proposed):
        f.unlink(missing_ok=True)
    if p["job"] in ("writeup", "new_page") and p["status"] != "conflict":
        st["curated"][p["target_rel"]] = today()   # a conflict leaves the page eligible for the next run
    from .common import STATE_FILE
    save_json(STATE_FILE, st)
    _finish_card(p, card, result)
    log(f"{pid} {p['job']} {p['title']}: {result}")
    return result


def _apply(p: dict, proposed: Path, user: str) -> tuple[str, str]:
    if p["job"] == "hygiene":
        done = 0
        for e in p["edits"]:
            f = safe_rel(e["file"])
            if f.exists():
                t = f.read_text(encoding="utf-8")
                if t.count(e["old"]) >= 1:
                    f.write_text(t.replace(e["old"], e["new"]), encoding="utf-8")
                    done += 1
        p["status"] = "approved"
        return f"✅ Approved by {user} — {done}/{len(p['edits'])} edits applied", "approve"
    target = safe_rel(p["target_rel"])
    current = target.read_text(encoding="utf-8") if target.exists() else ""
    if p["base_sha256"] and sha(current) != p["base_sha256"]:
        p["status"] = "conflict"
        return f"⚠️ {Path(p['target_rel']).name} changed since this was proposed — not applied (re-queued next run)", "conflict"
    if not proposed.exists():
        p["status"] = "conflict"
        return "⚠️ proposed note was deleted — nothing applied", "conflict"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(proposed.read_text(encoding="utf-8"), encoding="utf-8")
    p["status"] = "approved"
    if p["job"] == "coverage":
        rebuild_coverage_index()
    return f"✅ Approved by {user} — written to {p['target_rel']}", "approve"


def rebuild_coverage_index() -> None:
    c = cfg()
    v = vault_root()
    rows = []
    for f in sorted((v / c["coverage_dir"]).glob("*.md")):
        fm = frontmatter(f.read_text(encoding="utf-8"))
        rows.append(f"| [[{f.stem}]] | {fm.get('techniques', '?')} | {fm.get('covered', '?')} | {fm.get('partial', '?')} | "
                    f"**{fm.get('gaps', '?')}** | {fm.get('updated', '')} |")
    (v / c["coverage_index"]).write_text(
        "---\ntitle: 00 - Threat Coverage Gaps\ntags: [detection/coverage, detection/moc]\n---\n\n"
        "# Threat Coverage Gaps\n\nPer-actor ATT&CK coverage of the vault's rule notes, maintained by the ioc-watcher curator. "
        "Technique sets come from each actor's writeup; coverage comes from rule `mitre_techniques`.\n\n"
        "| Actor | Techniques | Covered | Partial | Gaps | Updated |\n|---|---|---|---|---|---|\n" + "\n".join(rows) + "\n",
        encoding="utf-8")


def process_decisions() -> int:
    """Called by vault_sync every 15 min: pull button clicks from the Worker and apply them."""
    try:
        ds = fetch_decisions()
    except Exception as e:  # noqa: BLE001
        log(f"decision fetch failed: {e}")
        return 0
    done = []
    for d in ds:
        decide(d["id"], d["decision"], d.get("user", "?"))
        done.append(d["id"])
    ack(done)
    return len(done)


def pending_targets() -> set[str]:
    out = set()
    for f in PROPOSALS.glob("*.json"):
        p = load_json(f, {})
        if p.get("status") == "pending":
            out.add(p.get("target_rel") or "")
            out.add(p.get("title", ""))
    return out
