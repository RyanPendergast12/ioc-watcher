"""Curator shared bits: local paths, config, vault index, headless Claude runner.

Everything here runs on the laptop. Vault and detection content stays local (and goes to
Claude the same way any Claude Code session would). Nothing is committed to GitHub.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
LOCAL = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "ioc-watcher"
STORE = LOCAL / "curator"
PROPOSALS = STORE / "proposals"
LOGS = STORE / "logs"
STATE_FILE = STORE / "state.json"
ENV_FILE = LOCAL / "curator.env"
TCODE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
WIKILINK = re.compile(r"\[\[([^\]|#\n]+)(?:#[^\]|\n]*)?(?:\|[^\]\n]*)?\]\]")


def load_env() -> None:
    """KEY=VALUE lines from %LOCALAPPDATA%/ioc-watcher/curator.env into os.environ."""
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip().strip('"'))


def cfg() -> dict:
    return yaml.safe_load((REPO / "config" / "curator.yml").read_text(encoding="utf-8"))


def vault_root() -> Path:
    return Path(os.environ.get("IOC_WATCHER_VAULT") or cfg()["vault"])


def today() -> str:
    return dt.date.today().isoformat()


def sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def load_json(p: Path, default):
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def save_json(p: Path, data) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=1, ensure_ascii=False), encoding="utf-8")
    tmp.replace(p)


def state() -> dict:
    s = load_json(STATE_FILE, {})
    s.setdefault("curated", {})       # vault rel path -> date last proposed/applied
    s.setdefault("coverage", {})      # actor page rel -> date
    s.setdefault("missing_done", [])  # family names already proposed / rejected
    s.setdefault("last_hygiene", "")
    return s


def log(msg: str) -> None:
    line = f"{dt.datetime.now():%Y-%m-%d %H:%M:%S} [curator] {msg}"
    print(line, flush=True)
    LOCAL.mkdir(parents=True, exist_ok=True)
    with (LOCAL / "curator.log").open("a", encoding="utf-8") as f:
        f.write(line + "\n")


def words(text: str) -> int:
    body = re.sub(r"^---\n.*?\n---\n", "", text, flags=re.S)
    return len(re.findall(r"\w+", body))


# ------------------------------------------------------------------ vault index
@dataclass
class Rule:
    title: str
    rel: str
    rule_id: str
    status: str
    techniques: list[str]
    actors: list[str]


@dataclass
class Page:
    rel: str
    title: str
    category: str
    aliases: list[str] = field(default_factory=list)


def frontmatter(text: str) -> dict:
    m = re.match(r"^---\n(.*?)\n---\n", text, re.S)
    if not m:
        return {}
    try:
        return yaml.safe_load(m.group(1)) or {}
    except yaml.YAMLError:
        return {}


def profile_pages() -> list[Page]:
    mapping = yaml.safe_load((REPO / "config" / "mapping.yml").read_text(encoding="utf-8"))
    return [Page(t["path"], t["title"], t.get("category", ""), t.get("aliases", []) + t.get("strict", []))
            for t in mapping["targets"]]


def rules_index(vault: Path) -> list[Rule]:
    out = []
    for f in (vault / cfg()["rules_dir"]).rglob("*.md"):
        fm = frontmatter(f.read_text(encoding="utf-8", errors="replace"))
        techs = [str(t).strip() for t in (fm.get("mitre_techniques") or []) if TCODE.fullmatch(str(t).strip())]
        out.append(Rule(str(fm.get("title") or f.stem), f.relative_to(vault).as_posix(), str(fm.get("rule_id", "")),
                        str(fm.get("status", "")), techs, [str(a) for a in fm.get("threat_actors") or []]))
    return out


def coverage(techniques: list[str], rules: list[Rule]) -> dict[str, dict]:
    """technique -> {exact: [rule titles], related: [rule titles]} (parent/sub-technique overlap = related)."""
    res = {}
    for t in sorted(set(techniques)):
        parent = t.split(".")[0]
        exact, related = [], []
        for r in rules:
            if t in r.techniques:
                exact.append(r.title)
            elif any(x.split(".")[0] == parent for x in r.techniques):
                related.append(r.title)
        res[t] = {"exact": exact[:8], "related": related[:5], "n_exact": len(exact), "n_related": len(related)}
    return res


# ------------------------------------------------------------------ headless Claude
def claude_bin() -> str:
    for c in (shutil.which("claude"), str(Path.home() / ".local" / "bin" / "claude.exe"),
              str(Path.home() / ".local" / "bin" / "claude")):
        if c and Path(c).exists():
            return c
    raise FileNotFoundError("claude CLI not found")


def run_claude(prompt: str, job_id: str, timeout_min: int | None = None) -> str:
    """Read-only research session: may read the vault and the web, may not write anything."""
    c = cfg()
    cmd = [claude_bin(), "-p", "--output-format", "json",
           "--allowedTools", "Read,Glob,Grep,WebSearch,WebFetch",
           "--disallowedTools", "Write,Edit,NotebookEdit,Bash,PowerShell"]
    if c.get("model"):
        cmd += ["--model", c["model"]]
    LOGS.mkdir(parents=True, exist_ok=True)
    r = subprocess.run(cmd, input=prompt, cwd=str(vault_root()), capture_output=True, text=True, encoding="utf-8",
                       timeout=60 * (timeout_min or c.get("job_timeout_min", 25)))
    (LOGS / f"{today()}-{job_id}.json").write_text(r.stdout or r.stderr, encoding="utf-8")
    if r.returncode != 0:
        raise RuntimeError(f"claude exited {r.returncode}: {(r.stderr or r.stdout)[:300]}")
    data = json.loads(r.stdout)
    if data.get("is_error"):
        raise RuntimeError(f"claude error: {str(data.get('result'))[:300]}")
    return data.get("result", "")


def parse_output(text: str) -> dict:
    """SUMMARY: … / CHANGES: bullets / PATH: … / <<<PAGE … PAGE>>>"""
    out = {"summary": "", "changes": [], "path": "", "page": ""}
    m = re.search(r"<<<PAGE\n(.*?)\nPAGE>>>", text, re.S)
    if m:
        out["page"] = m.group(1).strip("\n") + "\n"
    head = text[: m.start()] if m else text
    if (s := re.search(r"^SUMMARY:\s*(.+)$", head, re.M)):
        out["summary"] = s.group(1).strip()
    if (p := re.search(r"^PATH:\s*(.+)$", head, re.M)):
        out["path"] = p.group(1).strip().strip("`").replace("\\", "/")
    if (c := re.search(r"^CHANGES:\s*\n((?:\s*[-*].*\n?)+)", head, re.M)):
        out["changes"] = [l.strip().lstrip("-* ").strip() for l in c.group(1).splitlines() if l.strip()][:8]
    if re.search(r"^NO_CHANGE", head, re.M):
        out["no_change"] = True
    return out
