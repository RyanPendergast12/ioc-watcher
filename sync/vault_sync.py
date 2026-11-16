"""Pull approved proposals from the ioc-watcher repo and append them to the Obsidian vault.

Runs on the laptop (Task Scheduler, every 15 min). The vault never leaves the machine:
GitHub only ever holds the proposals, this script does the writing.

    python sync/vault_sync.py                 # git pull + apply new approvals
    python sync/vault_sync.py --dry-run       # show what would be written
    python sync/vault_sync.py --no-pull

Each target page gets one managed section at the bottom:

    ## IOC Watcher
    ### Domains
    - `evil.xyz` — ThreatFox · Lumma Stealer botnet_cc · 2026-11-15
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEFAULT_VAULT = Path(os.environ.get("IOC_WATCHER_VAULT", r"C:\Users\Ryanp\Documents\Obsidian Vault"))
LEDGER = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "ioc-watcher" / "applied.json"
LOGFILE = LEDGER.with_name("sync.log")

SECTION = "## IOC Watcher"
HEADINGS = {
    "report": "### Recent Reporting",
    "cve": "### CISA KEV Additions",
    "domain": "### Domains",
    "onion": "### Onion / Tor",
    "ip": "### IP Addresses",
    "cidr": "### IP Ranges (CIDR)",
    "sha256": "### SHA256",
    "sha1": "### SHA1",
    "md5": "### MD5",
    "ssl_sha1": "### SSL Certificate Fingerprints (SHA1)",
}
ORDER = list(HEADINGS)


def log(msg: str) -> None:
    line = f"{dt.datetime.now():%Y-%m-%d %H:%M:%S} {msg}"
    print(line)
    LOGFILE.parent.mkdir(parents=True, exist_ok=True)
    with LOGFILE.open("a", encoding="utf-8") as f:
        f.write(line + "\n")


def fmt(item: dict, day: str) -> str:
    t = item["type"]
    if t == "report":
        title = (item.get("title") or item["value"]).replace("[", "(").replace("]", ")")
        pages = f" → {item['context']}" if item.get("context") else ""
        return f"- {item.get('published') or day} — [{title}]({item['value'].replace(' ', '%20')}) · {item.get('source', '')}{pages}"
    if t == "cve":
        rw = " · ⚠️ known ransomware use" if item.get("ransomware") else ""
        return (f"- {item.get('dateAdded') or day} — **[{item['value']}]({item.get('ref', '')})** "
                f"{item.get('context', '')}{rw} · due {item.get('dueDate', '?')}")
    ctx = f" · {item['context']}" if item.get("context") else ""
    return f"- `{item['value']}` — {item.get('source', '')}{ctx} · {day}"


def _digest_header(rel: str) -> str:
    name = Path(rel).stem
    return f"# Intel Feed — {name}\n\nNew research pulled by ioc-watcher. Links to vault pages show where a report was matched.\n"


def append(page: Path, items: list[dict], day: str, rel: str) -> int:
    text = page.read_text(encoding="utf-8") if page.exists() else (
        _digest_header(rel) if "Intel Feed" in rel else f"# {page.stem}\n")
    low = text.lower()
    fresh, batch = [], set()
    for i in items:
        v = i["value"].lower()
        if v in low or v.replace(" ", "%20") in low or v in batch:
            continue
        batch.add(v)
        fresh.append(i)
    if not fresh:
        return 0
    lines = text.rstrip("\n").split("\n")
    if sum(1 for l in lines if l.lstrip().startswith("```")) % 2:
        lines.append("```")  # page ends inside an open code block — close it first
    try:
        start = next(i for i, l in enumerate(lines) if l.strip() == SECTION)
    except StopIteration:
        lines += ["", SECTION, "<!-- appended by ioc-watcher after Discord approval; safe to edit -->"]
        start = len(lines) - 2
    end = next((i for i in range(start + 1, len(lines)) if lines[i].startswith("## ")), len(lines))

    by_type: dict[str, list[str]] = {}
    for i in fresh:
        by_type.setdefault(i["type"], []).append(fmt(i, day))

    for t in sorted(by_type, key=lambda x: ORDER.index(x) if x in ORDER else 99):
        head = HEADINGS.get(t, f"### {t}")
        sec = lines[start:end]
        if head in [l.strip() for l in sec]:
            h = start + [l.strip() for l in sec].index(head)
            j = h + 1
            while j < end and not lines[j].startswith("#"):
                j += 1
            while j - 1 > h and not lines[j - 1].strip():
                j -= 1
            lines[j:j] = by_type[t]
        else:
            block = ["", head, *by_type[t]]
            lines[end:end] = block
        end = next((i for i in range(start + 1, len(lines)) if lines[i].startswith("## ")), len(lines))

    page.parent.mkdir(parents=True, exist_ok=True)
    page.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return len(fresh)


def safe_target(vault: Path, rel: str) -> Path:
    p = (vault / rel).resolve()
    if vault.resolve() not in p.parents or p.suffix.lower() != ".md":
        raise ValueError(f"refusing to write outside vault / non-markdown: {rel!r}")
    return p


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--vault", default=str(DEFAULT_VAULT))
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--no-pull", action="store_true")
    a = ap.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    vault = Path(a.vault)
    if not vault.is_dir():
        log(f"vault not found: {vault}")
        return 1

    if not a.no_pull:
        r = subprocess.run(["git", "-C", str(REPO), "pull", "--ff-only", "--quiet"], capture_output=True, text=True)
        if r.returncode:
            log(f"git pull failed: {r.stderr.strip()[:300]}")

    ledger = json.loads(LEDGER.read_text(encoding="utf-8")) if LEDGER.exists() else {}
    total = 0
    for f in sorted((REPO / "approved").glob("*.json")):
        pid = f.stem
        if pid in ledger:
            continue
        p = json.loads(f.read_text(encoding="utf-8"))
        day = (p.get("decision", {}).get("at") or p.get("created") or "")[:10]
        try:
            target = safe_target(vault, p["target_md"])
        except ValueError as e:
            log(f"{pid}: {e}")
            continue
        items = [i for i in p["items"] if i.get("value")]
        if a.dry_run:
            print(f"[dry-run] {pid} → {p['target_md']} ({len(items)} items)")
            for i in items[:5]:
                print("    " + fmt(i, day))
            continue
        n = append(target, items, day, p["target_md"])
        ledger[pid] = {"at": dt.datetime.now().isoformat(timespec="seconds"), "target": p["target_md"], "written": n}
        total += n
        log(f"{pid}: +{n} lines → {p['target_md']} (approved by {p.get('decision', {}).get('by', '?')})")
    if not a.dry_run:
        LEDGER.parent.mkdir(parents=True, exist_ok=True)
        LEDGER.write_text(json.dumps(ledger, indent=1), encoding="utf-8")
    if total:
        log(f"done: {total} new lines")
    if not a.dry_run:
        _curator_decisions()
    return 0


def _curator_decisions() -> None:
    """Apply Approve/Deny clicks on curator (writeup / coverage / hygiene) cards."""
    try:
        sys.path.insert(0, str(REPO))
        from curator.common import load_env
        from curator.store import process_decisions
        load_env()
        n = process_decisions()
        if n:
            log(f"curator: applied {n} decision(s)")
    except Exception as e:  # noqa: BLE001
        log(f"curator decisions failed: {e}")


if __name__ == "__main__":
    sys.exit(main())
