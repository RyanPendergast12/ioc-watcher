"""Daily detect run: fetch → extract → classify → write pending/<id>.json proposals.

    python -m watcher.detect              # normal run (writes pending/ + state/)
    python -m watcher.detect --dry-run    # print what would be proposed, change nothing
    python -m watcher.detect --only threatfox,dfir_report
"""
from __future__ import annotations

import argparse
import copy
import json
import os
import re
import sys
import time
from collections import Counter, defaultdict

from . import iocs
from .classify import Classifier
from .common import (PENDING, ROOT, get, load_state, load_yaml, log, new_id, now_iso, proposal_path,
                     prune_state, save_json, save_state, today)
from .sources import REGISTRY, Candidate, Ctx, SkipSource

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
# feeds whose tags are malware-family names (used to spot families with no vault page)
FAMILY_SOURCES = {"ThreatFox", "MalwareBazaar", "Feodo Tracker", "Abuse.ch SSLBL", "URLhaus", "AlienVault OTX"}
GENERIC_TAGS = {"unknown", "elf", "exe", "dll", "zip", "rar", "mirai", "32-bit", "64-bit", "arm", "mips", "x86",
                "malware", "trojan", "phishing", "c2", "botnet_cc", "payload_delivery", "none", "n/a", "signed",
                "doc", "xls", "js", "ps1", "vbs", "hta", "lnk", "msi", "iso", "apk", "sh", "bat"}

BUCKET_TYPES = {"ip": "ip", "cidr": "ip", "domain": "domain", "onion": "domain", "sha256": "hash", "sha1": "hash",
                "md5": "hash", "ssl_sha1": "hash"}


def load_tlds() -> None:
    try:
        txt = get("https://data.iana.org/TLD/tlds-alpha-by-domain.txt", timeout=20).text
        iocs.set_tlds({l.strip().lower() for l in txt.splitlines() if l and not l.startswith("#")})
    except Exception as e:  # noqa: BLE001
        log(f"TLD list unavailable ({e}); skipping TLD validation")


def run_sources(cfgs, ctx, only=None):
    results, health = [], {}
    for s in cfgs:
        name = s["name"]
        if only and name not in only:
            continue
        if not s.get("enabled", True):
            health[name] = "disabled"
            continue
        fn = REGISTRY[s["type"]]
        t0 = time.time()
        try:
            r = fn(s, ctx)
            n = len(r.candidates) + sum(len(v) for v in r.reputation.values()) + len(r.reports)
            health[name] = f"ok ({n} raw, {time.time() - t0:.0f}s)"
            r.kind = s.get("kind", "feed")  # type: ignore[attr-defined]
            r.name = name  # type: ignore[attr-defined]
            results.append(r)
        except SkipSource as e:
            health[name] = f"skipped: {e}"
        except Exception as e:  # noqa: BLE001
            health[name] = f"ERROR: {type(e).__name__}: {str(e)[:160]}"
        log(f"{name:<28} {health[name]}")
    return results, health


def build(results, clf: Classifier, mapping: dict, settings: dict, state: dict):
    buckets = mapping["buckets"]
    kev = settings.get("_kev", {})
    hash_types = tuple(settings.get("hash_types", ["sha256", "sha1", "md5"]))
    max_article_iocs = settings.get("max_iocs_per_article", 150)
    candidates: list[Candidate] = []
    reports_by_target: dict[str, list[dict]] = defaultdict(list)
    digest: list[dict] = []

    # ---- reports (blogs, repo files) → reporting links + extracted IOCs
    for r in results:
        for rep in r.reports:
            hits = clf.from_text(f"{rep.title} {rep.path_hint}", rep.body,
                                 min_score=settings.get("article_min_score", 3))
            # IOCs are only attributed when the page is the article's *subject* (named in its title / file path),
            # and never to tool or technique pages (a report "using Mimikatz" is not Mimikatz infrastructure).
            title_hits = clf.from_text(f"{rep.title} {rep.path_hint}", "", min_score=5)
            primary = next((t for t, _ in title_hits
                            if "Capabilities" not in t.path and "Techniques" not in t.path), None)
            entry = {"type": "report", "value": rep.url, "title": rep.title or rep.url, "source": rep.source,
                     "published": rep.published, "context": ", ".join(h[0].title for h in hits[:4])}
            if r.kind == "research":
                digest.append(entry)
            if r.kind in ("research", "reports", "repo"):
                for t, _score in hits[:3]:
                    reports_by_target[t.path].append(entry)
            if r.kind == "reports":
                continue
            ex = iocs.extract(rep.body, require_defang=rep.require_defang, hash_types=hash_types)
            cves = sorted({c.upper() for c in CVE_RE.findall(f"{rep.title} {rep.body}")})
            if len(cves) > settings.get("max_cves_per_report", 6):   # vuln round-ups: too ambiguous
                cves = [c for c in cves if c in rep.title.upper()]
            products = sorted({kev[c] for c in cves if c in kev})
            n = 0
            for t, v in ex.items():
                if n >= max_article_iocs:
                    break
                c = Candidate(t, v, rep.source, context=(rep.title or rep.path_hint)[:70], ref=rep.url,
                              route_unmapped=settings.get("route_unmapped_report_iocs", False))
                if primary:
                    c.extra["target"] = primary.path
                if cves:
                    c.extra["cves"] = cves
                if products:
                    c.extra["products"] = products
                candidates.append(c)
                n += 1
        candidates.extend(r.candidates)

    # ---- multi-feed IP consensus
    rep_feeds: dict[str, set[str]] = {}
    for r in results:
        rep_feeds.update(r.reputation)
    counts: Counter = Counter()
    who: dict[str, list[str]] = defaultdict(list)
    for feed, ips in rep_feeds.items():
        for ip in ips:
            counts[ip] += 1
            who[ip].append(feed)
    min_feeds = settings.get("consensus_min_feeds", 2)
    for ip, n in counts.most_common():
        if n < min_feeds:
            break
        candidates.append(Candidate("ip", ip, f"Consensus ({n} feeds)", context="+".join(sorted(who[ip]))[:80]))

    # ---- resolve targets, validate, de-dupe
    seen = state["seen"]
    unmatched: Counter = Counter()
    grouped: dict[str, dict[str, dict]] = defaultdict(dict)
    for c in candidates:
        v = iocs.normalize(c.value, c.type)
        if not iocs.is_valid(v, c.type):
            continue
        key = f"{c.type}:{v}"
        if key in seen:
            continue
        target = c.extra.get("target")
        if not target and c.type == "cve":
            target = buckets["kev"]
        if not target:
            t = clf.from_tags(*c.tags) if c.tags else None
            target = t.path if t else None
            fam = next((str(x).strip() for x in c.tags if x and str(x).strip()), "")
            if not t and fam and c.source in FAMILY_SOURCES and fam.lower() not in GENERIC_TAGS:
                unmatched[fam] += 1
        tag_cves = [str(x).upper() for x in c.tags if x and CVE_RE.fullmatch(str(x))]
        if tag_cves and "cves" not in c.extra:
            c.extra["cves"] = tag_cves
            c.extra["products"] = sorted({kev[x] for x in tag_cves if x in kev})
        if not target and c.route_unmapped:
            target = buckets.get(BUCKET_TYPES.get(c.type, ""))
        if not target:
            continue
        g = grouped[target]
        if key in g:
            if c.source not in g[key]["source"]:
                g[key]["source"] += f", {c.source}"
            continue
        item = {"type": c.type, "value": v, "source": c.source, "context": c.context, "ref": c.ref}
        fam = next((str(x).strip() for x in c.tags if x and str(x).strip().lower() not in GENERIC_TAGS
                    and not CVE_RE.fullmatch(str(x).strip())), "")
        if fam:
            item["family"] = fam[:60]
        item.update({k: val for k, val in c.extra.items() if k != "target"})
        g[key] = item

    # ---- proposals
    titles = {t["path"]: t["title"] for t in mapping["targets"]}
    bucket_paths = {p for k, p in buckets.items() if k not in ("kev", "digest_dir")}
    cap = settings.get("max_items_per_proposal", 75)
    bucket_cap = settings.get("max_items_per_bucket", 60)
    proposals = []
    stamp = now_iso()
    for target in sorted(set(grouped) | set(reports_by_target)):
        items = list(grouped.get(target, {}).values())
        kind = "kev" if target == buckets["kev"] else "bucket" if target in bucket_paths else "iocs"
        limit = bucket_cap if kind == "bucket" else cap
        items.sort(key=_priority)
        if kind == "bucket":
            items = _per_source_cap(items, settings.get("max_per_source_in_bucket", 20))
        overflow = max(0, len(items) - limit)
        items = items[:limit]
        reports = _dedupe_reports(reports_by_target.get(target, []))
        if not items and not reports:
            continue
        title = titles.get(target) or target.rsplit("/", 1)[-1].removesuffix(".md")
        headline = {"iocs": f"New IOC proposal — {title}", "bucket": f"Raw intel — {title}",
                    "kev": f"CISA KEV — {len(items)} new"}[kind]
        proposals.append({"id": new_id(), "created": stamp, "kind": kind, "target_md": target,
                          "headline": headline, "items": items + reports, "reports": reports,
                          "overflow": overflow, "status": "pending"})
    if digest:
        d = _dedupe_reports(digest)
        proposals.append({"id": new_id(), "created": stamp, "kind": "digest",
                          "target_md": f"{buckets['digest_dir']}/{today()}.md",
                          "headline": f"Intel digest — {today()} ({len(d)} new reports)",
                          "items": d, "reports": [], "overflow": 0, "status": "pending"})
    return proposals, unmatched


def _priority(i):
    """Multi-source corroboration first, then consensus strength, then type."""
    m = re.match(r"Consensus \((\d+) feeds\)", i["source"])
    strength = i["source"].count(",") + 1 + (int(m.group(1)) if m else 0)
    return (-strength, i["type"])


def _per_source_cap(items, cap):
    used, out = Counter(), []
    for i in items:
        first = i["source"].split(",")[0]
        if used[first] < cap or "," in i["source"]:
            used[first] += 1
            out.append(i)
    return out


def _dedupe_reports(rs):
    out, seen = [], set()
    for r in rs:
        if r["value"] not in seen:
            seen.add(r["value"])
            out.append(r)
    return out


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--only", default="")
    ap.add_argument("--bootstrap", action="store_true", help="force bootstrap look-back window")
    ap.add_argument("--days", type=int, help="one-off look-back of N days (implies --bootstrap)")
    a = ap.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    settings = load_yaml("settings.yml")
    mapping = load_yaml("mapping.yml")
    srcs = load_yaml("sources.yml")["sources"]
    state = load_state()
    work_state = copy.deepcopy(state)
    bootstrap = a.bootstrap or bool(a.days) or not state["initialized"]
    if a.days:
        settings["bootstrap_days"] = a.days
        settings["html_bootstrap_items"] = max(3, a.days)
        settings["_kev_days"] = a.days
    settings["_mb_signatures"] = mapping.get("mb_signatures", [])
    clf = Classifier(mapping)
    load_tlds()
    log(f"bootstrap={bootstrap} targets={len(clf.targets)}")

    ctx = Ctx(work_state, bootstrap, settings)
    results, health = run_sources(srcs, ctx, only=set(filter(None, a.only.split(","))))
    proposals, unmatched = build(results, clf, mapping, settings, work_state)
    um = work_state.setdefault("unmatched", {})
    for fam, n in unmatched.items():
        e = um.setdefault(fam, {"count": 0, "days": 0, "last_seen": ""})
        e["count"] += n
        if e["last_seen"] != today():
            e["days"] += 1
            e["last_seen"] = today()

    summary = [f"# Detect run {now_iso()}", "", f"bootstrap: {bootstrap}", "", "## Proposals"]
    for p in proposals:
        summary.append(f"- `{p['id']}` {p['headline']} — {len(p['items'])} items → `{p['target_md']}`")
    summary += ["", "## Source health", "| source | status |", "|---|---|"]
    summary += [f"| {k} | {v} |" for k, v in health.items()]
    text = "\n".join(summary) + "\n"
    print(text)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as f:
            f.write(text)

    if a.dry_run:
        out = ROOT / "dry-run"
        out.mkdir(exist_ok=True)
        for p in proposals:
            save_json(out / f"{p['id']}.json", p)
        log(f"dry run: wrote {len(proposals)} proposals to {out}")
        return 0

    for p in proposals:
        save_json(proposal_path(p["id"]), p)
        for i in p["items"]:
            if i["type"] != "report":
                work_state["seen"][f"{i['type']}:{i['value']}"] = today()
    work_state["initialized"] = True
    prune_state(work_state, settings.get("seen_retention_days", 180))
    save_state(work_state)
    (ROOT / "state" / "last_run.md").write_text(text, encoding="utf-8")
    log(f"wrote {len(proposals)} proposals to {PENDING}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
