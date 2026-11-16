"""Nightly vault curator.

    python -m curator.run                         # full nightly pass (per config/curator.yml)
    python -m curator.run --job hygiene           # one job only: writeup | coverage | missing | hygiene
    python -m curator.run --job writeup --target "Threat Intel/Threat Actors → APT + Nation-State/APT29.md"
    python -m curator.run --plan                  # show what tonight's run would pick, run nothing
    python -m curator.run --decide <id> approve   # apply a decision locally (no Discord needed)
"""
from __future__ import annotations

import argparse
import datetime as dt
import subprocess
import sys

from . import jobs, store
from .common import REPO, cfg, load_env, log, state


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--job", choices=["writeup", "coverage", "missing", "hygiene"])
    ap.add_argument("--target", help="vault-relative page (writeup/coverage) or family name (missing)")
    ap.add_argument("--plan", action="store_true")
    ap.add_argument("--decide", nargs=2, metavar=("ID", "approve|deny"))
    a = ap.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    load_env()

    if a.decide:
        print(store.decide(a.decide[0], a.decide[1], "local"))
        return 0

    subprocess.run(["git", "-C", str(REPO), "pull", "--ff-only", "--quiet"], capture_output=True)
    n = cfg()["nightly"]
    hyg_day = dt.date.today().weekday() == n.get("hygiene_weekday", 6)
    plan = {
        "writeup": [a.target] if a.target and a.job == "writeup" else jobs.refresh_candidates(n["writeup_refresh"]),
        "coverage": [a.target] if a.target and a.job == "coverage" else jobs.coverage_candidates(n["coverage_gaps"]),
        "missing": ([(a.target, {"count": "?", "days": "?", "last_seen": "?"})] if a.target and a.job == "missing"
                    else jobs.missing_candidates(n["missing_pages"])),
        "hygiene": [True] if (hyg_day or a.job == "hygiene") else [],
    }
    if a.job:
        plan = {k: (v if k == a.job else []) for k, v in plan.items()}
    log("plan: " + "; ".join(f"{k}={[x[0] if isinstance(x, tuple) else x for x in v]}" for k, v in plan.items()))
    if a.plan:
        return 0

    made = []
    runners = {"writeup": jobs.writeup, "coverage": jobs.coverage_gaps,
               "missing": lambda x: jobs.new_page(*x), "hygiene": lambda _x: jobs.hygiene()}
    for job, items in plan.items():
        for item in items:
            try:
                p = runners[job](item)
            except Exception as e:  # noqa: BLE001 — one failed job must not stop the night
                log(f"{job} {item}: FAILED {type(e).__name__}: {str(e)[:300]}")
                continue
            if p:
                store.post(p)
                made.append(p)
                log(f"proposed {p['id']} {job}: {p['title']} — {p['summary'][:120]}")
    log(f"done: {len(made)} proposals")
    return 0


if __name__ == "__main__":
    sys.exit(main())
