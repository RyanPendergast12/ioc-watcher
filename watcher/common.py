"""Shared helpers: paths, config, state, HTTP session, proposal files, git."""
from __future__ import annotations

import datetime as dt
import json
import os
import subprocess
import time
import uuid
from pathlib import Path

import requests
import yaml

ROOT = Path(__file__).resolve().parent.parent
CONFIG = ROOT / "config"
STATE_FILE = ROOT / "state" / "state.json"
PENDING = ROOT / "pending"
APPROVED = ROOT / "approved"
DENIED = ROOT / "archive" / "denied"

UA_BROWSER = "Mozilla/5.0 (compatible; ioc-watcher/1.0; RSS/feed reader)"


def today() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d")


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def load_yaml(name: str) -> dict:
    return yaml.safe_load((CONFIG / name).read_text(encoding="utf-8")) or {}


def load_json(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return default


def save_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=False, ensure_ascii=False) + "\n", encoding="utf-8")
    tmp.replace(path)


# ------------------------------------------------------------------ state
def load_state() -> dict:
    s = load_json(STATE_FILE, {})
    s.setdefault("version", 1)
    s.setdefault("initialized", False)
    s.setdefault("seen", {})        # "type:value" -> first proposed date
    s.setdefault("rss", {})         # feed url -> [seen links]
    s.setdefault("html", {})        # page url -> [seen links]
    s.setdefault("github", {})      # owner/repo -> last checked iso
    s.setdefault("kev", [])         # cve ids already processed
    return s


def prune_state(s: dict, keep_days: int = 180) -> None:
    cutoff = (dt.date.today() - dt.timedelta(days=keep_days)).isoformat()
    s["seen"] = {k: v for k, v in s["seen"].items() if v >= cutoff}
    s["unmatched"] = {k: v for k, v in s.get("unmatched", {}).items() if v.get("last_seen", "") >= cutoff[:10]}
    for bucket in ("rss", "html"):
        for k, v in s[bucket].items():
            s[bucket][k] = v[-500:]


def save_state(s: dict) -> None:
    save_json(STATE_FILE, s)


# ------------------------------------------------------------------ http
_session: requests.Session | None = None


def http() -> requests.Session:
    global _session
    if _session is None:
        _session = requests.Session()
        _session.headers.update({"User-Agent": UA_BROWSER, "Accept": "*/*"})
    return _session


def get(url: str, timeout: int = 45, **kw) -> requests.Response:
    last = None
    for attempt in range(3):
        try:
            r = http().get(url, timeout=timeout, **kw)
            if r.status_code in (429, 502, 503, 504) and attempt < 2:
                time.sleep(3 * (attempt + 1))
                continue
            r.raise_for_status()
            return r
        except requests.RequestException as e:
            last = e
            time.sleep(2 * (attempt + 1))
    raise last  # type: ignore[misc]


def post(url: str, timeout: int = 60, **kw) -> requests.Response:
    r = http().post(url, timeout=timeout, **kw)
    r.raise_for_status()
    return r


# ------------------------------------------------------------------ proposals
def new_id() -> str:
    return uuid.uuid4().hex[:10]


def proposal_path(pid: str, folder: Path = PENDING) -> Path:
    if not pid.isalnum():
        raise ValueError(f"bad proposal id {pid!r}")
    return folder / f"{pid}.json"


def list_pending() -> list[dict]:
    out = []
    for p in sorted(PENDING.glob("*.json")):
        out.append(load_json(p, {}))
    return out


# ------------------------------------------------------------------ misc
def env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def repo_slug() -> str:
    return env("GITHUB_REPOSITORY", "RyanPendergast12/ioc-watcher")


def git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=ROOT, check=True, capture_output=True, text=True).stdout


def log(msg: str) -> None:
    print(f"[{dt.datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)
