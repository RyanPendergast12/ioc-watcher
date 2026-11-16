"""Regenerate config/mapping.yml from the Obsidian vault's Threat Intel taxonomy.

Run locally whenever you add/rename a profile page:
    python tools/build_mapping.py --vault "C:/Users/Ryanp/Documents/Obsidian Vault"
Only file *names* leave the vault — no page content is read or published.
"""
from __future__ import annotations

import argparse
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
PROFILE_DIRS = [
    "Threat Intel/Malware Families",
    "Threat Intel/Threat Actors → APT + Nation-State",
    "Threat Intel/Threat Actors → Cybercrime + Other",
    "Threat Intel/Threat Intel → Capabilities",
    "Threat Intel/Threat Intel → Techniques + Tradecraft",
]
BUCKETS = {
    "ip": "Threat Intel/Raw Threat Intel/BAD IPS.md",
    "domain": "Threat Intel/Raw Threat Intel/BAD DOMAINS.md",
    "hash": "Threat Intel/Raw Threat Intel/BAD HASHES.md",
    "kev": "Vulnerability Management/CISA KEV.md",
    "digest_dir": "Threat Intel/Intel Feed",
}


def auto_aliases(title: str) -> list[str]:
    out = {title}
    m = re.match(r"(.+?)\s*\(aka\s+(.+?)\)", title, re.I)
    if m:
        out |= {m.group(1), m.group(2)}
    for part in re.split(r"\s+\+\s+|\s+-\s*|\s*→\s*", title):
        if part.strip():
            out.add(part.strip())
    m = re.match(r"(APT\d+)\b\s*(.*)", title)
    if m:
        out.add(m.group(1))
        if m.group(2):
            out.add(m.group(2).strip(" -"))
    return sorted(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--vault", default=r"C:\Users\Ryanp\Documents\Obsidian Vault")
    a = ap.parse_args()
    vault = Path(a.vault)
    curated = yaml.safe_load((ROOT / "config" / "aliases.yml").read_text(encoding="utf-8"))
    pages = curated.get("pages", {})
    targets = []
    for d in PROFILE_DIRS:
        for f in sorted((vault / d).rglob("*.md")):
            title = f.stem
            cur = pages.get(title, {})
            if cur.get("skip"):
                continue
            rel = f.relative_to(vault).as_posix()
            strict = list(cur.get("strict", []))
            aliases = list(cur.get("aliases", []))
            for al in auto_aliases(title):
                n = re.sub(r"[^a-z0-9]", "", al.lower())
                if title in pages and "aliases" in cur:
                    continue  # curated entry wins
                if len(n) < 5 and al not in strict:
                    strict.append(al)
                elif al not in aliases:
                    aliases.append(al)
            targets.append({"path": rel, "title": title, "category": f.parent.name,
                            "aliases": aliases, "strict": strict})
    missing = sorted(set(pages) - {t["title"] for t in targets} - {k for k, v in pages.items() if v.get("skip")})
    out = {"generated_from": "tools/build_mapping.py", "buckets": BUCKETS,
           "mb_signatures": curated.get("mb_signatures", []), "targets": targets}
    (ROOT / "config" / "mapping.yml").write_text(
        "# GENERATED — edit config/aliases.yml and re-run tools/build_mapping.py\n"
        + yaml.safe_dump(out, sort_keys=False, allow_unicode=True, width=140), encoding="utf-8")
    print(f"{len(targets)} targets written")
    if missing:
        print("curated titles with no vault page:", ", ".join(missing))


if __name__ == "__main__":
    main()
