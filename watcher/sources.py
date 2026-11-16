"""Source fetchers. Each returns a SourceResult; failures are isolated per source."""
from __future__ import annotations

import csv
import datetime as dt
import io
import json
import re
import time
from dataclasses import dataclass, field
from urllib.parse import urljoin

import feedparser

from . import iocs
from .common import env, get, log, post

# ------------------------------------------------------------------ model


@dataclass
class Candidate:
    type: str                 # ip | cidr | domain | sha256 | sha1 | md5 | ssl_sha1 | cve
    value: str
    source: str
    context: str = ""         # family / reason / file path, shown in Discord + vault
    tags: tuple = ()          # family hints used for classification
    ref: str = ""             # link back to the evidence
    route_unmapped: bool = True   # if no vault page matches, send to Raw Threat Intel bucket
    extra: dict = field(default_factory=dict)


@dataclass
class Report:
    title: str
    url: str
    source: str
    published: str = ""
    summary: str = ""
    body: str = ""            # plain text (for classification + IOC extraction)
    require_defang: bool = True
    path_hint: str = ""       # for repo files: path used in classification


@dataclass
class SourceResult:
    candidates: list[Candidate] = field(default_factory=list)
    reputation: dict[str, set[str]] = field(default_factory=dict)   # feed name -> ips
    reports: list[Report] = field(default_factory=list)
    status: str = "ok"


class Ctx:
    def __init__(self, state: dict, bootstrap: bool, settings: dict):
        self.state = state
        self.bootstrap = bootstrap
        self.settings = settings
        self.now = dt.datetime.now(dt.timezone.utc)

    @property
    def lookback(self) -> dt.datetime:
        days = self.settings.get("bootstrap_days", 3) if self.bootstrap else self.settings.get("max_lookback_days", 7)
        return self.now - dt.timedelta(days=days)


def _slug(s: str) -> str:
    return re.sub(r"-+", "-", re.sub(r"[^a-z0-9]+", "-", (s or "unknown").lower())).strip("-") or "unknown"


def _lines(text: str):
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith(("#", ";", "//")):
            yield line


# ------------------------------------------------------------------ abuse.ch (Auth-Key required since 2025)
def _abusech_headers():
    key = env("ABUSECH_AUTH_KEY")
    if not key:
        raise SkipSource("ABUSECH_AUTH_KEY not set")
    return {"Auth-Key": key}


class SkipSource(Exception):
    pass


def threatfox(cfg, ctx) -> SourceResult:
    r = post("https://threatfox-api.abuse.ch/api/v1/", headers=_abusech_headers(),
             json={"query": "get_iocs", "days": cfg.get("days", 1)}).json()
    res = SourceResult()
    min_conf = cfg.get("min_confidence", 75)
    for row in r.get("data") or []:
        if int(row.get("confidence_level") or 0) < min_conf:
            continue
        t, v = row.get("ioc_type", ""), row.get("ioc", "")
        if t == "ip:port":
            t, v = "ip", v.rsplit(":", 1)[0]
        elif t == "url":
            h = iocs.host_of(v)
            if not h:
                continue
            t, v = ("ip" if iocs.IPV4_RE.fullmatch(h) else "domain"), h
        elif t in ("sha256_hash", "md5_hash", "sha1_hash"):
            t = t.split("_")[0]
        elif t != "domain":
            continue
        fam = row.get("malware_printable") or ""
        res.candidates.append(Candidate(
            t, v, "ThreatFox", context=f"{fam} {row.get('threat_type', '')}".strip(),
            tags=(fam, row.get("malware"), row.get("malware_alias"), *(row.get("tags") or [])),
            ref=f"https://threatfox.abuse.ch/ioc/{row.get('id')}/"))
    return res


def malwarebazaar(cfg, ctx) -> SourceResult:
    hdr = _abusech_headers()
    res = SourceResult()
    hash_types = cfg.get("hash_types", ["sha256"])
    rows = post("https://mb-api.abuse.ch/api/v1/", headers=hdr,
                data={"query": "get_recent", "selector": "100"}).json().get("data") or []
    # targeted pulls for families that have a vault page (signature names are CamelCase)
    for sig in ctx.settings.get("_mb_signatures", [])[: cfg.get("max_signature_queries", 80)]:
        try:
            d = post("https://mb-api.abuse.ch/api/v1/", headers=hdr,
                     data={"query": "get_siginfo", "signature": sig, "limit": cfg.get("per_signature", 25)}).json()
            if d.get("query_status") == "ok":
                rows.extend(d.get("data") or [])
        except Exception as e:  # noqa: BLE001
            log(f"  MB siginfo {sig}: {e}")
        time.sleep(0.25)
    cutoff = ctx.lookback.strftime("%Y-%m-%d %H:%M:%S")
    for row in rows:
        if (row.get("first_seen") or "") < cutoff:
            continue
        sig = row.get("signature") or ""
        for ht in hash_types:
            h = row.get(f"{ht}_hash")
            if h:
                res.candidates.append(Candidate(
                    ht, h, "MalwareBazaar", context=f"{sig or 'unknown'} {row.get('file_type', '')}".strip(),
                    tags=(sig, *(row.get("tags") or [])),
                    ref=f"https://bazaar.abuse.ch/sample/{row.get('sha256_hash')}/",
                    route_unmapped=bool(sig) or cfg.get("route_unsigned", False)))
    return res


def urlhaus(cfg, ctx) -> SourceResult:
    d = post(f"https://urlhaus-api.abuse.ch/v1/urls/recent/limit/{cfg.get('limit', 1000)}/",
             headers=_abusech_headers()).json()
    res = SourceResult()
    for row in d.get("urls") or []:
        h = iocs.host_of(row.get("url", ""))
        if not h:
            continue
        tags = tuple(row.get("tags") or [])
        t = "ip" if iocs.IPV4_RE.fullmatch(h) else "domain"
        res.candidates.append(Candidate(
            t, h, "URLhaus", context=f"{row.get('threat', '')} {' '.join(tags)}".strip(), tags=tags,
            ref=row.get("urlhaus_reference", ""), route_unmapped=cfg.get("route_unmapped", True)))
    return res


def feodo(cfg, ctx) -> SourceResult:
    res = SourceResult()
    for row in get("https://feodotracker.abuse.ch/downloads/ipblocklist.json").json():
        fam = row.get("malware", "")
        res.candidates.append(Candidate("ip", row["ip_address"], "Feodo Tracker",
                                        context=f"{fam} C2 :{row.get('port')}", tags=(fam,),
                                        ref=f"https://feodotracker.abuse.ch/browse/host/{row['ip_address']}/"))
    res.reputation["feodo"] = {c.value for c in res.candidates}
    return res


def sslbl(cfg, ctx) -> SourceResult:
    res = SourceResult()
    cutoff = ctx.lookback.strftime("%Y-%m-%d")
    txt = get("https://sslbl.abuse.ch/blacklist/sslblacklist.csv").text
    for line in _lines(txt):
        parts = line.split(",", 2)
        if len(parts) == 3 and parts[0][:10] >= cutoff:
            reason = parts[2]
            res.candidates.append(Candidate("ssl_sha1", parts[1].lower(), "Abuse.ch SSLBL",
                                            context=reason, tags=(reason.replace(" C&C", ""),),
                                            ref=f"https://sslbl.abuse.ch/ssl-certificates/sha1/{parts[1]}/"))
    ips = get("https://sslbl.abuse.ch/blacklist/sslipblacklist.csv").text
    res.reputation["sslbl_ip"] = {l.split(",")[1] for l in _lines(ips) if l.count(",") >= 2}
    return res


# ------------------------------------------------------------------ IP reputation lists (consensus only)
def iplist(cfg, ctx) -> SourceResult:
    """Plain-text IP / CIDR list. Contributes to the multi-feed consensus, never proposed alone."""
    txt = get(cfg["url"]).text
    ips = set()
    for line in _lines(txt):
        tok = re.split(r"[\s,;]+", line)[0]
        if iocs.IPV4_RE.fullmatch(tok):
            ips.add(tok)
    return SourceResult(reputation={cfg["name"]: ips})


def isc_sans(cfg, ctx) -> SourceResult:
    rows = get("https://isc.sans.edu/api/sources/attacks/100?json").json()
    ips = {re.sub(r"\b0+(\d)", r"\1", r["ip"]) for r in rows if isinstance(r, dict) and r.get("ip")}
    return SourceResult(reputation={"isc_sans": ips})


def abuseipdb(cfg, ctx) -> SourceResult:
    key = env("ABUSEIPDB_API_KEY")
    if not key:
        raise SkipSource("ABUSEIPDB_API_KEY not set")
    d = get("https://api.abuseipdb.com/api/v2/blacklist", headers={"Key": key, "Accept": "application/json"},
            params={"confidenceMinimum": cfg.get("min_confidence", 100), "limit": 10000}).json()
    return SourceResult(reputation={"abuseipdb": {r["ipAddress"] for r in d.get("data", []) if ":" not in r["ipAddress"]}})


def spamhaus_drop(cfg, ctx) -> SourceResult:
    """Only *newly listed* ranges are proposed; the first run just records a baseline."""
    res = SourceResult()
    snaps = ctx.state.setdefault("snap", {})
    known = set(snaps.get("spamhaus_drop", []))
    current = []
    for line in get("https://www.spamhaus.org/drop/drop_v4.json").text.splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "cidr" in row:
            current.append(row["cidr"])
            if not known or row["cidr"] in known:
                continue
            res.candidates.append(Candidate("cidr", row["cidr"], "Spamhaus DROP", context=row.get("sblid", ""),
                                            ref=f"https://check.spamhaus.org/sbl/query/{row.get('sblid', '')}"))
    snaps["spamhaus_drop"] = sorted(current)
    return res


def cidrlist(cfg, ctx) -> SourceResult:
    """Plain-text CIDR list (e.g. StopForumSpam toxic ranges). Baselines first, then proposes new ranges."""
    res = SourceResult()
    snaps = ctx.state.setdefault("snap", {})
    known = set(snaps.get(cfg["name"], []))
    current = [l.split()[0] for l in _lines(get(cfg["url"]).text) if iocs.CIDR_RE.fullmatch(l.split()[0])]
    for c in current:
        if known and c not in known:
            res.candidates.append(Candidate("cidr", c, cfg["name"], context=cfg.get("context", "")))
    snaps[cfg["name"]] = sorted(current)
    return res


# ------------------------------------------------------------------ domain / url lists
def urllist(cfg, ctx) -> SourceResult:
    """Line-based URL or domain list (OpenPhish, VXVault, CyberCrime Tracker, CoinBlocker)."""
    res = SourceResult()
    txt = get(cfg["url"]).text
    seen = set()
    for line in _lines(re.sub(r"(?i)</?pre>", "\n", txt)):
        tok = iocs.refang(line.split()[0])
        if "://" not in tok and "/" in tok:
            tok = "http://" + tok
        h = iocs.host_of(tok) if "://" in tok else tok.lower()
        if not h or h in seen:
            continue
        seen.add(h)
        t = "ip" if iocs.IPV4_RE.fullmatch(h) else "domain"
        res.candidates.append(Candidate(t, h, cfg["name"], context=cfg.get("context", ""),
                                        route_unmapped=cfg.get("route_unmapped", True)))
    cap = cfg.get("max_items")
    if cap:
        res.candidates = res.candidates[:cap]
    return res


def phishtank(cfg, ctx) -> SourceResult:
    res = SourceResult()
    cutoff = ctx.lookback.isoformat()[:19]
    rdr = csv.DictReader(io.StringIO(get("https://data.phishtank.com/data/online-valid.csv", timeout=90).text))
    for row in rdr:
        if (row.get("submission_time") or "")[:19] < cutoff:
            continue
        h = iocs.host_of(row.get("url", ""))
        if h:
            res.candidates.append(Candidate("ip" if iocs.IPV4_RE.fullmatch(h) else "domain", h, "PhishTank",
                                            context=f"phish {row.get('target', '')}".strip(),
                                            ref=row.get("phish_detail_url", "")))
    return res


def tweetfeed(cfg, ctx) -> SourceResult:
    res = SourceResult()
    for row in get("https://api.tweetfeed.live/v1/today").json():
        t, v = row.get("type"), row.get("value", "")
        tags = tuple(x.lstrip("#") for x in row.get("tags") or [])
        if t == "url":
            h = iocs.host_of(v)
            if not h:
                continue
            t, v = ("ip" if iocs.IPV4_RE.fullmatch(h) else "domain"), h
        if t not in ("ip", "domain", "sha256", "md5"):
            continue
        res.candidates.append(Candidate(t, v, "TweetFeed", context=f"@{row.get('user', '')} {' '.join('#' + x for x in tags)}",
                                        tags=tags, ref=row.get("tweet", ""),
                                        route_unmapped=cfg.get("route_unmapped", False)))
    return res


def otx(cfg, ctx) -> SourceResult:
    key = env("OTX_API_KEY")
    if not key:
        raise SkipSource("OTX_API_KEY not set")
    res = SourceResult()
    since = ctx.lookback.strftime("%Y-%m-%dT%H:%M:%S") if ctx.bootstrap else (ctx.now - dt.timedelta(days=1, hours=2)).strftime("%Y-%m-%dT%H:%M:%S")
    url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
    params = {"modified_since": since, "limit": 50}
    pages = 0
    tmap = {"IPv4": "ip", "domain": "domain", "hostname": "domain", "FileHash-SHA256": "sha256",
            "FileHash-MD5": "md5", "FileHash-SHA1": "sha1"}
    while url and pages < cfg.get("max_pages", 6):
        d = get(url, headers={"X-OTX-API-KEY": key}, params=params).json()
        params = None
        pages += 1
        for p in d.get("results", []):
            fams = [f.get("display_name") if isinstance(f, dict) else f for f in p.get("malware_families") or []]
            tags = (*fams, p.get("adversary"), *(p.get("tags") or []))
            for ind in p.get("indicators", [])[: cfg.get("max_per_pulse", 200)]:
                t = tmap.get(ind.get("type"))
                if t:
                    res.candidates.append(Candidate(t, ind["indicator"], "AlienVault OTX", context=p.get("name", "")[:80],
                                                    tags=tags, ref=f"https://otx.alienvault.com/pulse/{p.get('id')}",
                                                    route_unmapped=cfg.get("route_unmapped", False)))
            res.reports.append(Report(p.get("name", ""), f"https://otx.alienvault.com/pulse/{p.get('id')}",
                                      "AlienVault OTX", p.get("modified", "")[:10], summary=(p.get("description") or "")[:300]))
        url = d.get("next")
    res.reports = [] if not cfg.get("pulses_as_reports", False) else res.reports
    return res


# ------------------------------------------------------------------ CISA KEV
def cisa_kev(cfg, ctx) -> SourceResult:
    d = get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json").json()
    res = SourceResult()
    known = set(ctx.state.get("kev", []))
    cutoff = (ctx.now - dt.timedelta(days=ctx.settings.get("_kev_days") or cfg.get("bootstrap_days", 7))).strftime("%Y-%m-%d")
    all_ids = []
    kev_products = ctx.settings.setdefault("_kev", {})
    for v in d.get("vulnerabilities", []):
        cid = v["cveID"]
        all_ids.append(cid)
        kev_products[cid] = f"{_slug(v.get('vendorProject', ''))}/{_slug(v.get('product', ''))}"
        if cid in known:
            continue
        if not known and v.get("dateAdded", "") < cutoff:
            continue
        res.candidates.append(Candidate("cve", cid, "CISA KEV", context=f"{v.get('vendorProject')} {v.get('product')} — {v.get('vulnerabilityName')}",
                                        ref=f"https://nvd.nist.gov/vuln/detail/{cid}",
                                        extra={"dateAdded": v.get("dateAdded"), "dueDate": v.get("dueDate"),
                                               "ransomware": v.get("knownRansomwareCampaignUse") == "Known",
                                               "notes": v.get("shortDescription", "")[:300]}))
    ctx.state["kev"] = all_ids
    return res


# ------------------------------------------------------------------ research blogs (RSS / HTML index)
def _fetch_article(url: str) -> tuple[str, str]:
    """Return (title, plain text) for an article URL; ("", "") on failure."""
    try:
        html = get(url, timeout=40).content.decode("utf-8", errors="replace")
    except Exception as e:  # noqa: BLE001
        log(f"    article fetch failed {url}: {e}")
        return "", ""
    import html as _h
    m = (re.search(r'<meta[^>]+property="og:title"[^>]+content="([^"]+)"', html, re.I)
         or re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S))
    title = _h.unescape(m.group(1)).strip() if m else ""
    title = re.split(r"\s+[|–—-]\s+(?=[^|–—-]*$)", title)[0].strip() if title else ""
    return title, iocs.strip_html(html)[:400_000]


def rss(cfg, ctx) -> SourceResult:
    res = SourceResult()
    seen = ctx.state["rss"].setdefault(cfg["url"], [])
    raw = get(cfg["url"], timeout=40).content
    feed = feedparser.parse(raw)
    if not feed.entries:
        raise RuntimeError("feed parsed with 0 entries")
    fetched = 0
    for e in feed.entries[:40]:
        link = e.get("link") or e.get("id")
        if not link or link in seen:
            continue
        seen.append(link)
        ts = e.get("published_parsed") or e.get("updated_parsed")
        pub = dt.datetime(*ts[:6], tzinfo=dt.timezone.utc) if ts else ctx.now
        if pub < ctx.lookback:
            continue
        title = (e.get("title") or "").strip()
        summary = iocs.strip_html(e.get("summary") or "")[:600].strip()
        content = " ".join(iocs.strip_html(c.get("value", "")) for c in e.get("content") or [])
        if len(content) < 1500 and fetched < cfg.get("max_fetch", 15):
            content = _fetch_article(link)[1] or content
            fetched += 1
        res.reports.append(Report(title, link, cfg["name"], pub.strftime("%Y-%m-%d"), summary=summary,
                                  body=content or summary))
    return res


def html_index(cfg, ctx) -> SourceResult:
    """Blogs with no RSS (ReliaQuest, Trend Micro): scrape the index for article links."""
    res = SourceResult()
    seen = ctx.state["html"].setdefault(cfg["url"], [])
    first_run = not seen
    page = get(cfg["url"]).text
    links = []
    for href in re.findall(r'href="([^"#?]+)"', page):
        full = urljoin(cfg["url"], href)
        if re.search(cfg["link_pattern"], full) and full.rstrip("/") != cfg["url"].rstrip("/") and full not in links:
            links.append(full)
    for link in links[: cfg.get("max_links", 25)]:
        if link in seen:
            continue
        seen.append(link)
        if first_run and len(res.reports) >= cfg.get("bootstrap_items", ctx.settings.get("html_bootstrap_items", 3)):
            continue
        title, body = _fetch_article(link)
        title = title or _title_from(link)
        res.reports.append(Report(title, link, cfg["name"], ctx.now.strftime("%Y-%m-%d"), body=body,
                                  summary=body[:300]))
    return res


def _title_from(link: str) -> str:
    slug = link.rstrip("/").rsplit("/", 1)[-1].replace(".html", "")
    return slug.replace("-", " ").strip().capitalize()


# ------------------------------------------------------------------ GitHub IOC repos
def github_repo(cfg, ctx) -> SourceResult:
    """New/changed files since last run. Uses commit patches so only *added* lines are read."""
    res = SourceResult()
    repo = cfg["repo"]
    hdr = {"Accept": "application/vnd.github+json"}
    tok = env("GITHUB_TOKEN") or env("GH_TOKEN")
    if tok:
        hdr["Authorization"] = f"Bearer {tok}"
    since = ctx.state["github"].get(repo) or ctx.lookback.isoformat()
    started = ctx.now.replace(microsecond=0).isoformat()
    commits = get(f"https://api.github.com/repos/{repo}/commits", headers=hdr,
                  params={"since": since, "per_page": cfg.get("max_commits", 20)}).json()
    exts = tuple(cfg.get("extensions", [".txt", ".csv", ".md", ".json", ".yar", ".yara", ".ioc", ".rules", ".tsv"]))
    mode = cfg.get("mode", "iocs")
    for c in commits:
        detail = get(c["url"], headers=hdr).json()
        msg = detail.get("commit", {}).get("message", "")
        for f in detail.get("files", []):
            name, status = f.get("filename", ""), f.get("status")
            if status == "removed":
                continue
            html_url = f"https://github.com/{repo}/blob/{c['sha']}/{name}"
            if mode == "reports":       # e.g. blackorbird/APT_REPORT: PDFs → reporting links only
                if status == "added" and re.search(cfg.get("report_pattern", r"\.pdf$"), name, re.I):
                    title = name.rsplit("/", 1)[-1].rsplit(".", 1)[0].replace("_", " ").replace("-", " ")
                    res.reports.append(Report(title, html_url, cfg["name"], ctx.now.strftime("%Y-%m-%d"),
                                              body="", path_hint=name, require_defang=False))
                continue
            if not name.lower().endswith(exts) and "." in name.rsplit("/", 1)[-1]:
                continue
            patch = f.get("patch")
            if patch:
                text = "\n".join(l[1:] for l in patch.splitlines() if l.startswith("+") and not l.startswith("+++"))
            elif f.get("raw_url") and (f.get("changes", 0) < 20000):
                try:
                    text = get(f["raw_url"]).text[:2_000_000]
                except Exception:  # noqa: BLE001
                    continue
            else:
                continue
            res.reports.append(Report(f"{name}", html_url, cfg["name"], ctx.now.strftime("%Y-%m-%d"),
                                      body=text, require_defang=False, path_hint=f"{name} {msg}"))
    ctx.state["github"][repo] = started
    return res


REGISTRY = {
    "threatfox": threatfox, "malwarebazaar": malwarebazaar, "urlhaus": urlhaus, "feodo": feodo,
    "sslbl": sslbl, "iplist": iplist, "isc_sans": isc_sans, "abuseipdb": abuseipdb,
    "spamhaus_drop": spamhaus_drop, "cidrlist": cidrlist, "urllist": urllist, "phishtank": phishtank, "tweetfeed": tweetfeed,
    "otx": otx, "cisa_kev": cisa_kev, "rss": rss, "html_index": html_index, "github_repo": github_repo,
}
