"""Post every pending proposal that has not been sent to Discord yet.

Runs after detect has committed pending/ so a Discord message never points at a proposal
that is missing from the repo. Safe to re-run: posted proposals carry a `discord` key.
"""
from __future__ import annotations

import sys
import time

from . import discord
from .common import env, list_pending, log, proposal_path, save_json


def main() -> int:
    if not env("DISCORD_BOT_TOKEN"):
        log("DISCORD_BOT_TOKEN not set; nothing posted")
        return 0
    posted = 0
    for p in list_pending():
        if p.get("discord"):
            continue
        try:
            p["discord"] = discord.post_proposal(p)
        except Exception as e:  # noqa: BLE001
            log(f"post {p['id']} failed: {e}")
            continue
        save_json(proposal_path(p["id"]), p)
        posted += 1
        time.sleep(1.1)  # stay under the 5 msg / 5 s channel limit
    log(f"posted {posted} proposals")
    return 0


if __name__ == "__main__":
    sys.exit(main())
