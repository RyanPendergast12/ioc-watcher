"""The four curator jobs. Each returns a created proposal (or None)."""
from __future__ import annotations

import datetime as dt
import difflib
import re
from pathlib import Path

from .common import (LOCAL, REPO, TCODE, WIKILINK, cfg, coverage, load_json, log, parse_output,
                     profile_pages, rules_index, run_claude, state, today, vault_root, words)
from . import store

HOUSE_RULES = """\
House rules for this vault:
- Match the existing page's structure, headings and tone; it is the user's own work. Keep everything that is
  still accurate. Don't delete IOCs, links or the user's notes; mark superseded claims instead of removing them.
- Keep any `## IOC Watcher` section exactly as-is at the bottom of the page.
- Cite sources inline (vendor + month/year) for every new claim. Prefer primary research (vendor blogs, CISA/FBI).
- Use MITRE ATT&CK IDs (T####/T####.###) wherever you describe behaviour.
- No filler. If nothing material has changed, reply with a single line: NO_CHANGE
"""

OUTPUT_FMT = """\
Reply in EXACTLY this format (nothing before SUMMARY):
SUMMARY: <one sentence: what changed and why it matters>
CHANGES:
- <change 1>
- <change 2 … up to 6>
{path_line}<<<PAGE
<the COMPLETE page content, ready to save>
PAGE>>>
"""


def _skill() -> str:
    p = Path(cfg()["writeup_skill"])
    return p.read_text(encoding="utf-8") if p.exists() else ""


def _ioc_section(text: str) -> str:
    m = re.search(r"\n## IOC Watcher\n.*", text, re.S)
    return m.group(0) if m else ""


# ------------------------------------------------------------------ 1. writeup refresh
def refresh_candidates(n: int) -> list[str]:
    c, st, v = cfg(), state(), vault_root()
    busy = store.pending_targets()
    cooldown = (dt.date.today() - dt.timedelta(days=c["refresh_cooldown_days"])).isoformat()
    ledger = load_json(LOCAL / "applied.json", {})
    fresh_intel = {}
    for e in ledger.values():   # pages that received approved IOC Watcher additions
        fresh_intel[e["target"]] = max(fresh_intel.get(e["target"], ""), e["at"][:10])
    scored = []
    for pg in profile_pages():
        f = v / pg.rel
        if not f.exists() or pg.rel in busy or st["curated"].get(pg.rel, "") >= cooldown:
            continue
        text = f.read_text(encoding="utf-8", errors="replace")
        mtime = dt.date.fromtimestamp(f.stat().st_mtime).isoformat()
        if pg.rel in fresh_intel and fresh_intel[pg.rel] > st["curated"].get(pg.rel, ""):
            scored.append((0, fresh_intel[pg.rel], pg.rel))
        elif words(text) < c["stub_words"]:
            scored.append((1, mtime, pg.rel))
        elif mtime < (dt.date.today() - dt.timedelta(days=c["stale_after_days"])).isoformat():
            scored.append((2, mtime, pg.rel))
    scored.sort()
    return [r for _, _, r in scored[:n]]


def writeup(rel: str):
    v = vault_root()
    text = (v / rel).read_text(encoding="utf-8", errors="replace")
    title = Path(rel).stem
    stub = words(text) < cfg()["stub_words"]
    task = (f"The vault page `{rel}` is a stub. Research **{title}** and write the full profile page."
            if stub else
            f"Update the vault page `{rel}` (**{title}**) with what has been published since it was last revised. "
            f"Read the page first. Check its '## IOC Watcher → Recent Reporting' links (if any) and search for "
            f"newer reporting (new campaigns, TTP changes, tooling, infrastructure, victims, aliases, law-enforcement action).")
    prompt = f"""{task}

The page lives in an Obsidian threat-intel vault (you are in the vault root; read neighbouring pages for style).
Follow this writing guide — but DO NOT save files; return the page instead:

<writing_guide>
{_skill()}
</writing_guide>

{HOUSE_RULES}
{OUTPUT_FMT.format(path_line="")}"""
    out = parse_output(run_claude(prompt, f"writeup-{title[:30]}"))
    if out.get("no_change") or not out["page"]:
        log(f"writeup {title}: no change")
        st = state(); st["curated"][rel] = today()
        from .common import STATE_FILE, save_json
        save_json(STATE_FILE, st)
        return None
    page = out["page"]
    ioc = _ioc_section(text)
    if ioc and "## IOC Watcher" not in page:
        page = page.rstrip("\n") + "\n" + ioc
    if not stub and words(page) < 0.6 * words(text):
        log(f"writeup {title}: rejected — proposed page is much shorter than current (likely truncated)")
        return None
    return store.create("writeup", title, rel, page, out["summary"] or "Writeup refresh", out["changes"])


# ------------------------------------------------------------------ 2. coverage gaps
ACTOR_CATS = ("APT + Nation-State", "Cybercrime + Other", "Ransomware")


def coverage_candidates(n: int) -> list[str]:
    st, v = state(), vault_root()
    cooldown = (dt.date.today() - dt.timedelta(days=cfg()["refresh_cooldown_days"])).isoformat()
    busy = store.pending_targets()
    out = []
    for pg in profile_pages():
        if not any(c in pg.rel for c in ACTOR_CATS) or st["coverage"].get(pg.rel, "") >= cooldown:
            continue
        f = v / pg.rel
        if not f.exists() or words(f.read_text(encoding="utf-8", errors="replace")) < cfg()["stub_words"]:
            continue   # stubs get written up first
        cov_rel = f"{cfg()['coverage_dir']}/{pg.title}.md"
        if cov_rel in busy:
            continue
        out.append((st["coverage"].get(pg.rel, ""), pg.rel))
    out.sort()
    return [r for _, r in out[:n]]


def coverage_gaps(rel: str):
    v = vault_root()
    text = (v / rel).read_text(encoding="utf-8", errors="replace")
    title = Path(rel).stem
    rules = [r for r in rules_index(v) if r.status not in ("deprecated", "retired")]
    techs = sorted(set(TCODE.findall(text)))
    cov = coverage(techs, rules)
    table = "\n".join(f"| {t} | {c['n_exact']} | {c['n_related']} | {'; '.join(c['exact'][:4]) or '—'} |" for t, c in cov.items())
    actor_rules = [r.title for r in rules if any(title.lower() in a.lower() for a in r.actors)]
    cov_rel = f"{cfg()['coverage_dir']}/{title}.md"
    existing = (v / cov_rel).read_text(encoding="utf-8") if (v / cov_rel).exists() else ""
    prompt = f"""Detection coverage review for **{title}** (vault page `{rel}`).

You are in an Obsidian vault. Detection rule notes live in `{cfg()['rules_dir']}` (frontmatter: title, rule_id,
mitre_techniques, threat_actors, platform, log sources). Read the actor page and any rules you need.

ATT&CK techniques cited in the actor page, with the number of vault rules covering each
(exact = same technique ID; related = same parent technique):

| Technique | Exact rules | Related rules | Example covering rules |
|---|---|---|---|
{table or '| (page cites no technique IDs — derive them from the behaviour described in the page) | | | |'}

Rules that name this actor in `threat_actors`: {', '.join(actor_rules[:20]) or 'none'}

Write a coverage note that a detection engineer can act on:
1. If the page cites few/no technique IDs, first map the behaviours it describes to ATT&CK.
2. For each technique: Covered / Partial / Gap, naming the covering rule(s) as [[wikilinks]].
3. For every Gap or weak Partial, ranked by how central it is to this actor's intrusions: the concrete procedure
   this actor uses (from the page), a detection idea (logic sketch, required log source/telemetry), and a
   suggested phase folder under `{cfg()['rules_dir']}/Attack Life Cycle/`.
4. A short "Quick wins" list: gaps closable by tuning or extending an existing rule.

Start the page with YAML frontmatter exactly like:
---
title: {title} — Coverage
actor: "[[{title}]]"
techniques: <int>
covered: <int>
partial: <int>
gaps: <int>
updated: {today()}
tags: [detection/coverage]
---
{"The current coverage note is below; update it rather than starting over." + chr(10) + existing if existing else ""}

Do not save files.
{OUTPUT_FMT.format(path_line="")}"""
    out = parse_output(run_claude(prompt, f"coverage-{title[:30]}"))
    st = state(); st["coverage"][rel] = today()
    from .common import STATE_FILE, save_json
    save_json(STATE_FILE, st)
    if not out["page"]:
        return None
    return store.create("coverage", title, cov_rel, out["page"], out["summary"] or f"Coverage review for {title}",
                        out["changes"])


# ------------------------------------------------------------------ 3. missing pages
def missing_candidates(n: int) -> list[tuple[str, dict]]:
    c, st = cfg(), state()
    ws = load_json(REPO / "state" / "state.json", {})
    um = ws.get("unmatched", {})
    from watcher.classify import Classifier
    import yaml
    clf = Classifier(yaml.safe_load((REPO / "config" / "mapping.yml").read_text(encoding="utf-8")))
    busy = store.pending_targets()
    out = []
    for fam, e in um.items():
        if fam in st["missing_done"] or fam in busy or clf.from_tags(fam):
            continue
        if e.get("days", 0) >= c["missing_min_days"] or e.get("count", 0) >= c["missing_min_count"]:
            out.append((-(e.get("days", 0) * 100 + e.get("count", 0)), fam, e))
    out.sort()
    return [(f, e) for _, f, e in out[:n]]


def new_page(fam: str, evidence: dict):
    prompt = f"""The threat feeds this vault tracks keep reporting **{fam}** ({evidence.get('count')} IOCs over
{evidence.get('days')} day(s), last seen {evidence.get('last_seen')}), but the vault has no page for it.

1. Decide whether "{fam}" is a real, distinct malware family / tool / actor worth a profile page. If it is a
   generic label, a duplicate alias of something already in the vault (search the vault!), or too obscure to
   research meaningfully, reply with the single line: NO_CHANGE
2. Otherwise research it and write the profile page following the writing guide, choosing the destination
   folder from the guide's taxonomy. Do not save files.

<writing_guide>
{_skill()}
</writing_guide>

{HOUSE_RULES}
{OUTPUT_FMT.format(path_line="PATH: <vault-relative path, e.g. Threat Intel/Malware Families/Infostealers/" + fam + ".md>" + chr(10))}"""
    out = parse_output(run_claude(prompt, f"newpage-{fam[:30]}"))
    st = state()
    st["missing_done"].append(fam)
    from .common import STATE_FILE, save_json
    save_json(STATE_FILE, st)
    if out.get("no_change") or not out["page"] or not out["path"].startswith("Threat Intel/"):
        log(f"new page {fam}: skipped ({'not a real family' if out.get('no_change') else 'bad output'})")
        return None
    if (vault_root() / out["path"]).exists() and words((vault_root() / out["path"]).read_text(encoding="utf-8")) >= cfg()["stub_words"]:
        log(f"new page {fam}: {out['path']} already exists")
        return None
    return store.create("new_page", Path(out["path"]).stem, out["path"], out["page"],
                        out["summary"] or f"New page for {fam}", out["changes"])


# ------------------------------------------------------------------ 4. hygiene (no LLM)
def hygiene():
    v = vault_root()
    names = {}
    for f in v.rglob("*"):
        if f.is_file() and ".obsidian" not in f.parts and ".trash" not in f.parts:
            names.setdefault(f.stem.lower(), f.stem)
            names.setdefault(f.name.lower(), f.name)
    scope = [v / "Threat Intel", v / "Detection"]
    edits, unresolved, stubs, no_attack = [], {}, [], []
    lower_names = list(names)
    for root in scope:
        for f in root.rglob("*.md"):
            rel = f.relative_to(v).as_posix()
            if cfg()["inbox_dir"] in rel:
                continue
            text = f.read_text(encoding="utf-8", errors="replace")
            for m in WIKILINK.finditer(text):
                target = m.group(1).strip()
                key = target.split("/")[-1].lower()
                if key in names or (key + ".md") in names:
                    continue
                close = difflib.get_close_matches(key, lower_names, n=1, cutoff=0.88)
                if close:
                    fixed = m.group(0).replace(target, names[close[0]].removesuffix(".md"), 1)
                    edits.append({"file": rel, "old": m.group(0), "new": fixed})
                else:
                    unresolved.setdefault(target, []).append(rel)
            if rel.startswith("Threat Intel/") and "Raw Threat Intel" not in rel and "Intel Feed" not in rel:
                if words(text) < cfg()["stub_words"]:
                    stubs.append(rel)
                elif ("Malware Families" in rel or "Threat Actors" in rel) and not TCODE.search(text):
                    no_attack.append(rel)
    uniq = {(e["file"], e["old"]): e for e in edits}
    edits = list(uniq.values())
    # If several pages expect the same name, the *file* is probably misspelled (e.g. links say [[SocGholish]],
    # file is SocGlolish.md). Suggest renaming the file in Obsidian instead of breaking correct links.
    by_name: dict[str, list[dict]] = {}
    for e in edits:
        by_name.setdefault(WIKILINK.match(e["old"]).group(1).strip(), []).append(e)
    renames = []
    for wanted, es in by_name.items():
        if len({e["file"] for e in es}) >= 2:
            existing = WIKILINK.match(es[0]["new"]).group(1).strip()
            renames.append(f"- Rename `{existing}` → `{wanted}` ({len(es)} links expect this name; Obsidian updates links on rename)")
            edits = [e for e in edits if e not in es]
    unresolved = {t: fs for t, fs in unresolved.items() if re.search(r"\w", t)}
    st = state()
    st["last_hygiene"] = today()
    from .common import STATE_FILE, save_json
    save_json(STATE_FILE, st)
    if not (edits or unresolved or stubs or no_attack or renames):
        return None
    def section(head, lines):
        return [head, *(lines or ["- none"]), ""]

    md = (section("## Probably misspelled file names (rename by hand — not auto-applied)", renames)
          + section("## Broken links with a confident fix (applied on Approve)",
                    [f"- `{e['file']}`: `{e['old']}` → `{e['new']}`" for e in edits[:200]])
          + section("## Broken links with no obvious target (fix by hand or create the page)",
                    [f"- `[[{t}]]` in " + ", ".join(f"`{x}`" for x in sorted(set(fs))[:3])
                     for t, fs in sorted(unresolved.items())[:150]])
          + section(f"## Stub pages (< {cfg()['stub_words']} words) — queued for writeup refresh",
                    [f"- [[{Path(s).stem}]]" for s in sorted(stubs)])
          + section("## Profile pages with no ATT&CK technique IDs (coverage review can't score them)",
                    [f"- [[{Path(s).stem}]]" for s in sorted(no_attack)]))
    summary = (f"{len(renames)} file renames suggested, {len(edits)} broken links auto-fixable, {len(unresolved)} unresolved, {len(stubs)} stubs, "
               f"{len(no_attack)} profiles without ATT&CK IDs")
    return store.create("hygiene", f"Week of {today()}", None, None, summary, [], edits=edits, extra_md="\n".join(md))
