"""Publish approved IOCs into the three private IOC repos.

    ioc-hashes   sha256 / sha1 / md5 / ssl-sha1
    ioc-domains  domains / onion
    ioc-ips      ips / cidrs

Layout (same in every repo, one folder per group, one file per IOC type):

    threat-actors/apt/<actor>/            threat-actors/cybercrime/<actor>/
    ransomware/<group>/                   malware/<category>/<family>/
    tools/<category>/<tool>/              techniques/<technique>/
    cves/<CVE-ID>/                        products/<vendor>/<product>/
    unattributed/<kind>/                  (phishing, c2-panels, reputation-consensus, …)
    all/<type>.txt                        everything, de-duplicated — point blocklists here
    index.csv                             value,type,group,source,context,first_seen,proposal,approved_by,ref

    python -m watcher.publish <proposal_id> [<id> …]     # used by the apply workflow
    python -m watcher.publish --all                       # backfill every approved proposal
"""
from __future__ import annotations

import argparse
import csv
import io
import re
import subprocess
import sys
import tempfile
from collections import defaultdict
from pathlib import Path

from .common import APPROVED, env, load_json, log

OWNER = env("IOC_REPOS_OWNER", "RyanPendergast12")
REPOS = {"hashes": "ioc-hashes", "domains": "ioc-domains", "ips": "ioc-ips"}
TYPE_REPO = {"sha256": "hashes", "sha1": "hashes", "md5": "hashes", "ssl_sha1": "hashes",
             "domain": "domains", "onion": "domains", "ip": "ips", "cidr": "ips"}
TYPE_FILE = {"sha256": "sha256.txt", "sha1": "sha1.txt", "md5": "md5.txt", "ssl_sha1": "ssl-sha1.txt",
             "domain": "domains.txt", "onion": "onion.txt", "ip": "ips.txt", "cidr": "cidrs.txt"}
CSV_FIELDS = ["value", "type", "group", "source", "context", "first_seen", "proposal", "approved_by", "ref"]

UNATTRIBUTED = [  # (source substring, folder) — first match wins
    ("Consensus", "reputation-consensus"), ("openphish", "phishing"), ("PhishTank", "phishing"),
    ("vxvault", "malware-distribution"), ("URLhaus", "malware-distribution"),
    ("cybercrime_tracker", "c2-panels"), ("Spamhaus", "hijacked-ranges"), ("stopforumspam", "abusive-ranges"),
    ("SSLBL", "ssl-c2-certificates"), ("Feodo", "botnet-c2"), ("MalwareBazaar", "malware-samples"), ("ThreatFox", "malware-infrastructure"),
    ("TweetFeed", "community"), ("OTX", "community"), ("manual", "manual"),
]


def slug(s: str) -> str:
    return re.sub(r"-+", "-", re.sub(r"[^a-z0-9]+", "-", s.lower())).strip("-") or "unknown"


def group_dirs(target_md: str, item: dict) -> list[str]:
    """Primary group folder from the vault page, plus CVE / product folders when known."""
    parts = target_md.split("/")
    stem = slug(Path(target_md).stem)
    if "Raw Threat Intel" in target_md and item.get("family"):
        primary = f"malware/unclassified/{slug(item['family'])}"   # known family, no vault page yet
    elif "Raw Threat Intel" in target_md:
        src = item.get("source", "")
        g = next((f for k, f in UNATTRIBUTED if k.lower() in src.lower()), "misc")
        primary = f"unattributed/{g}"
    elif "APT + Nation-State" in target_md:
        primary = f"threat-actors/apt/{stem}"
    elif "Cybercrime + Other" in target_md:
        primary = f"threat-actors/cybercrime/{stem}"
    elif "Ransomware" in target_md:
        primary = f"ransomware/{stem}"
    elif "Malware Families" in target_md:
        primary = f"malware/{slug(parts[-2])}/{stem}"
    elif "Capabilities" in target_md:
        primary = f"tools/{slug(parts[-2])}/{stem}"
    elif "Techniques" in target_md:
        primary = f"techniques/{stem}"
    else:
        primary = f"other/{stem}"
    out = [primary]
    out += [f"cves/{c.upper()}" for c in item.get("cves", [])]
    out += [f"products/{p}" for p in item.get("products", [])]
    return out


def _run(*args, cwd=None):
    return subprocess.run(args, cwd=cwd, check=True, capture_output=True, text=True).stdout


def _clone(repo: str, dest: Path) -> None:
    tok = env("IOC_REPOS_TOKEN")
    tmpl = env("IOC_REPOS_URL_TEMPLATE")  # tests: e.g. file:///tmp/remotes/{repo}.git
    url = tmpl.format(repo=repo) if tmpl else (f"https://x-access-token:{tok}@github.com/{OWNER}/{repo}.git" if tok
           else f"https://github.com/{OWNER}/{repo}.git")
    _run("git", "clone", "--depth", "1", "--quiet", url, str(dest))
    if not _has_head(dest):  # empty repo, or remote HEAD not pointing at main
        if subprocess.run(["git", "fetch", "-q", "--depth", "1", "origin", "main"], cwd=dest, capture_output=True).returncode == 0:
            _run("git", "checkout", "-q", "-B", "main", "FETCH_HEAD", cwd=dest)
        else:
            _run("git", "symbolic-ref", "HEAD", "refs/heads/main", cwd=dest)
    _run("git", "config", "user.name", "ioc-watcher[bot]", cwd=dest)
    _run("git", "config", "user.email", "ioc-watcher@users.noreply.github.com", cwd=dest)


def _has_head(dest: Path) -> bool:
    return subprocess.run(["git", "rev-parse", "--verify", "-q", "HEAD"], cwd=dest, capture_output=True).returncode == 0


def _merge_file(path: Path, values: set[str], header: str) -> int:
    existing = set()
    if path.exists():
        existing = {l.strip() for l in path.read_text(encoding="utf-8").splitlines() if l.strip() and not l.startswith("#")}
    new = values - existing
    if not new and path.exists():
        return 0
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(header + "\n".join(sorted(existing | values)) + "\n", encoding="utf-8")
    return len(new)


def _readme(root: Path, kind: str) -> None:
    rows = []
    for f in sorted(root.rglob("*.txt")):
        rel = f.relative_to(root).as_posix()
        if rel.startswith("all/"):
            continue
        n = sum(1 for l in f.read_text(encoding="utf-8").splitlines() if l.strip() and not l.startswith("#"))
        rows.append(f"| `{rel}` | {n} |")
    totals = []
    for f in sorted((root / "all").glob("*.txt")):
        n = sum(1 for l in f.read_text(encoding="utf-8").splitlines() if l.strip() and not l.startswith("#"))
        totals.append(f"**{f.stem}**: {n}")
    (root / "README.md").write_text(
        f"# ioc-{kind}\n\nHuman-approved {kind} IOCs from [ioc-watcher](https://github.com/{OWNER}/ioc-watcher). "
        "Every entry was approved in Discord before landing here.\n\n"
        f"Totals — {' · '.join(totals) or 'none yet'}\n\n"
        "* `all/<type>.txt` — everything, one per line (blocklist / SIEM reference-list friendly)\n"
        "* `<group>/<type>.txt` — per actor, family, CVE, product or unattributed source\n"
        "* `index.csv` — metadata: source, context, first seen, proposal id, approver, reference\n\n"
        "| file | entries |\n|---|---|\n" + "\n".join(rows) + "\n", encoding="utf-8")


def publish(proposals: list[dict], init: bool = False) -> dict:
    # bucket: repo -> relative file -> set(values); plus csv rows per repo
    files: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    rows: dict[str, list[dict]] = defaultdict(list)
    for p in proposals:
        approver = p.get("decision", {}).get("by", "")
        day = (p.get("decision", {}).get("at") or p.get("created", ""))[:10]
        for it in p.get("items", []):
            t = it.get("type")
            repo = TYPE_REPO.get(t)
            if not repo:
                continue
            dirs = group_dirs(p["target_md"], it)
            for d in dirs:
                files[repo][f"{d}/{TYPE_FILE[t]}"].add(it["value"])
            files[repo][f"all/{TYPE_FILE[t]}"].add(it["value"])
            rows[repo].append({"value": it["value"], "type": t, "group": dirs[0], "source": it.get("source", ""),
                               "context": it.get("context", ""), "first_seen": day, "proposal": p["id"],
                               "approved_by": approver, "ref": it.get("ref", "")})
    summary = {}
    ids = ", ".join(p["id"] for p in proposals)[:200]
    if init:
        for k in REPOS:
            files[k]  # touch so every repo is visited
    with tempfile.TemporaryDirectory() as tmp:
        for repo_key, fmap in files.items():
            root = Path(tmp) / repo_key
            _clone(REPOS[repo_key], root)
            added = 0
            for rel, vals in fmap.items():
                group = rel.rsplit("/", 1)[0]
                header = f"# {group} — {rel.rsplit('/', 1)[1][:-4]} — managed by ioc-watcher, human-approved\n"
                if rel.startswith("all/"):
                    added += _merge_file(root / rel, vals, f"# all {rel[4:-4]} — managed by ioc-watcher\n")
                else:
                    _merge_file(root / rel, vals, header)
            idx = root / "index.csv"
            seen = set()
            if idx.exists():
                for r in csv.DictReader(io.StringIO(idx.read_text(encoding="utf-8"))):
                    seen.add((r["value"], r["group"]))
            new_rows = [r for r in rows[repo_key] if (r["value"], r["group"]) not in seen]
            if new_rows:
                write_header = not idx.exists()
                with idx.open("a", encoding="utf-8", newline="") as f:
                    w = csv.DictWriter(f, fieldnames=CSV_FIELDS)
                    if write_header:
                        w.writeheader()
                    w.writerows(new_rows)
            _readme(root, repo_key)
            _run("git", "add", "-A", cwd=root)
            if subprocess.run(["git", "diff", "--cached", "--quiet"], cwd=root).returncode == 0:
                summary[REPOS[repo_key]] = 0
                continue
            _run("git", "commit", "-q", "-m", f"approve {ids}: +{added} entries", cwd=root)
            for _ in range(3):
                if subprocess.run(["git", "push", "-q", "origin", "HEAD:main"], cwd=root).returncode == 0:
                    break
                _run("git", "pull", "--rebase", "-q", "origin", "main", cwd=root)
            summary[REPOS[repo_key]] = added
            log(f"{REPOS[repo_key]}: +{added}")
    return summary


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("ids", nargs="*")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--init", action="store_true", help="write README/layout into empty repos")
    a = ap.parse_args(argv)
    if env("GITHUB_ACTIONS") and not env("IOC_REPOS_TOKEN") and not env("IOC_REPOS_URL_TEMPLATE"):
        log("IOC_REPOS_TOKEN secret not set; skipping IOC repo publish")
        return 0
    if a.init:
        log(f"init: {publish([], init=True)}")
        return 0
    paths = sorted(APPROVED.glob("*.json")) if a.all else [APPROVED / f"{i}.json" for i in a.ids if i.isalnum()]
    proposals = [p for p in (load_json(x, None) for x in paths) if p]
    if not proposals:
        log("nothing to publish")
        return 0
    log(f"published: {publish(proposals)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
