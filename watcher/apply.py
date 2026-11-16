"""Apply an Approve / Deny / Edit decision delivered by repository_dispatch.

Payload (github.event.client_payload, passed in the PAYLOAD env var as JSON):
    {proposal_id, decision: approve|deny, user, user_id, channel_id, message_id,
     remove: "lines…", add: "lines…"}          # remove/add only for Edit → Approve
"""
from __future__ import annotations

import argparse
import json
import sys

from . import discord, iocs
from .common import APPROVED, DENIED, env, load_json, log, now_iso, proposal_path, save_json


def _lines(text: str) -> list[str]:
    return [l.strip().strip("`- ") for l in (text or "").splitlines() if l.strip()]


def apply_edits(p: dict, remove: str, add: str, user: str) -> dict:
    rm = {iocs.normalize(v, iocs.classify_value(v) or "domain") for v in _lines(remove)}
    rm |= {v.lower() for v in _lines(remove)}
    before = len(p["items"])
    p["items"] = [i for i in p["items"] if i["value"].lower() not in rm and i["value"] not in rm]
    added = 0
    existing = {i["value"] for i in p["items"]}
    for raw in _lines(add):
        t = iocs.classify_value(raw)
        if not t:
            continue
        v = iocs.normalize(raw, t)
        if t == "url":
            h = iocs.host_of(v)
            if not h:
                continue
            t, v = ("ip" if iocs.IPV4_RE.fullmatch(h) else "domain"), h
        if v in existing:
            continue
        existing.add(v)
        p["items"].append({"type": t, "value": v, "source": f"manual ({user})", "context": "", "ref": ""})
        added += 1
    p["edit"] = {"removed": before - (len(p["items"]) - added), "added": added}
    return p


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--report-failure", action="store_true")
    a = ap.parse_args(argv)
    payload = json.loads(env("PAYLOAD") or "{}")
    pid = str(payload.get("proposal_id", ""))
    decision = payload.get("decision")
    user = str(payload.get("user", "unknown"))[:64]
    ch, mid = payload.get("channel_id"), payload.get("message_id")

    if a.report_failure:
        run = f"https://github.com/{env('GITHUB_REPOSITORY')}/actions/runs/{env('GITHUB_RUN_ID')}"
        p = load_json(proposal_path(pid), None)
        if p and ch and mid:
            discord.update_message(ch, mid, discord.build_embed(p, "error", f"⚠️ apply failed — {run}"),
                                   discord.buttons(pid))
        return 0

    allowed = {u.strip() for u in env("DISCORD_ALLOWED_USER_IDS").split(",") if u.strip()}
    if allowed and str(payload.get("user_id")) not in allowed:
        log(f"user {payload.get('user_id')} not allowed")
        return 1
    if decision not in ("approve", "deny"):
        log(f"bad decision {decision!r}")
        return 1

    src = proposal_path(pid)
    p = load_json(src, None)
    if p is None:
        log(f"proposal {pid} not pending (already decided?)")
        return 0

    if decision == "approve" and (payload.get("remove") or payload.get("add")):
        p = apply_edits(p, payload.get("remove", ""), payload.get("add", ""), user)

    p["status"] = "approved" if decision == "approve" else "denied"
    p["decision"] = {"by": user, "user_id": str(payload.get("user_id", "")), "at": now_iso()}
    dest = proposal_path(pid, APPROVED if decision == "approve" else DENIED)
    save_json(dest, p)
    src.unlink()
    log(f"{pid} -> {dest}")

    if ch and mid and env("DISCORD_BOT_TOKEN"):
        note = (f"✅ Approved by {user}" + (f" (edited: -{p['edit']['removed']} +{p['edit']['added']})" if p.get("edit") else "")
                + " — queued for vault sync") if decision == "approve" else f"❌ Denied by {user} — archived"
        discord.update_message(ch, mid, discord.build_embed(p, decision, note))
    return 0


if __name__ == "__main__":
    sys.exit(main())
