"""IOC extraction, refanging, defanging and validation."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path

# ---------------------------------------------------------------- patterns
_REFANG = [
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)|\s\[\.\]\s", re.I), "."),
    (re.compile(r"\[:\]", re.I), ":"),
    (re.compile(r"\[://\]", re.I), "://"),
    (re.compile(r"\bhxxp", re.I), "http"),
    (re.compile(r"\bfxp", re.I), "ftp"),
    (re.compile(r"\[at\]|\(at\)", re.I), "@"),
]
_DEFANG_MARK = re.compile(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)|hxxp|\[:\]|\[://\]", re.I)

IPV4_RE = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\d.]|\.\d)")
CIDR_RE = re.compile(IPV4_RE.pattern + r"/(?:3[0-2]|[12]?\d)\b")
DOMAIN_RE = re.compile(r"(?<![\w@.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,23}(?![\w-])", re.I)
SHA256_RE = re.compile(r"(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])", re.I)
SHA1_RE = re.compile(r"(?<![0-9a-f])[0-9a-f]{40}(?![0-9a-f])", re.I)
MD5_RE = re.compile(r"(?<![0-9a-f])[0-9a-f]{32}(?![0-9a-f])", re.I)
ONION_RE = re.compile(r"(?:[a-z0-9-]+\.)*(?:[a-z2-7]{16}|[a-z2-7]{56})\.onion")
URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s\"'<>\]\)]+", re.I)

# Real TLDs that collide with file extensions / code — only trusted when defanged.
CONFUSABLE_TLDS = {"zip", "mov", "py", "sh", "ps", "pl", "rs", "md", "so", "app", "run", "cs", "sys"}
NEVER_TLDS = {"exe", "dll", "js", "json", "txt", "png", "jpg", "jpeg", "gif", "php", "html", "htm",
              "aspx", "asp", "bat", "cmd", "ps1", "vbs", "lnk", "msi", "hta", "jar", "sys", "tmp",
              "log", "ini", "cfg", "dat", "bin", "iso", "img", "doc", "docx", "xls", "xlsx", "pdf",
              "rar", "7z", "gz", "tar", "yml", "yaml", "xml", "css", "csv", "lua", "go", "rb", "ts",
              "cpp", "hpp", "c", "h", "java", "class", "elf", "dylib", "plist", "svg", "pyc",
              "local", "lan", "internal", "corp", "localdomain", "example", "invalid", "test"}

_DATA = Path(__file__).resolve().parent.parent / "config"


def _load_set(name: str) -> set[str]:
    p = _DATA / name
    if not p.exists():
        return set()
    out = set()
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip().lower()
        if line:
            out.add(line)
    return out


ALLOW_DOMAINS = _load_set("allowlist_domains.txt")
ALLOW_IPS = _load_set("allowlist_ips.txt")
_TLDS: set[str] | None = None


def set_tlds(tlds: set[str]) -> None:
    global _TLDS
    _TLDS = {t.lower() for t in tlds}


# ---------------------------------------------------------------- helpers
def refang(text: str) -> str:
    for rx, rep in _REFANG:
        text = rx.sub(rep, text)
    return text


def defang(value: str, ioc_type: str) -> str:
    if ioc_type in ("domain", "onion", "ip", "cidr", "url"):
        value = value.replace("http", "hxxp", 1) if ioc_type == "url" else value
        head, dot, tail = value.rpartition(".")
        return f"{head}[.]{tail}" if dot else value
    return value


def registrable(domain: str) -> str:
    parts = domain.lower().strip(".").split(".")
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in {"co", "com", "net", "org", "gov", "ac", "edu", "or", "ne", "go"}:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def is_allowlisted_domain(domain: str) -> bool:
    d = domain.lower().strip(".")
    return d in ALLOW_DOMAINS or registrable(d) in ALLOW_DOMAINS


def valid_domain(domain: str, defanged: bool = False) -> bool:
    d = domain.lower().strip(".")
    if "." not in d or len(d) > 253:
        return False
    tld = d.rsplit(".", 1)[1]
    if tld == "onion":
        return bool(ONION_RE.fullmatch(d))
    if tld in NEVER_TLDS:
        return False
    if _TLDS is not None and tld not in _TLDS:
        return False
    if not defanged and tld in CONFUSABLE_TLDS:
        return False
    if is_allowlisted_domain(d):
        return False
    return True


def valid_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if not addr.is_global or addr.is_multicast:
        return False
    return ip not in ALLOW_IPS


def valid_cidr(cidr: str) -> bool:
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False
    return net.is_global and net.prefixlen >= 8


def host_of(url: str) -> str | None:
    m = re.match(r"^[a-z]+://(?:[^@/]*@)?([^/:?#]+)", url.strip(), re.I)
    return m.group(1).lower() if m else None


def classify_value(value: str) -> str | None:
    """Best-effort type for a single, already-isolated value (used for manual edits / feeds)."""
    v = refang(value.strip()).strip("`'\" ")
    if not v:
        return None
    if CIDR_RE.fullmatch(v):
        return "cidr"
    if IPV4_RE.fullmatch(v):
        return "ip"
    if SHA256_RE.fullmatch(v):
        return "sha256"
    if SHA1_RE.fullmatch(v):
        return "sha1"
    if MD5_RE.fullmatch(v):
        return "md5"
    if URL_RE.fullmatch(v):
        return "url"
    if re.fullmatch(r"CVE-\d{4}-\d{4,}", v, re.I):
        return "cve"
    if ONION_RE.fullmatch(v.lower()):
        return "onion"
    if DOMAIN_RE.fullmatch(v):
        return "domain"
    return None


def normalize(value: str, ioc_type: str) -> str:
    v = refang(value.strip()).strip("`'\" ")
    if ioc_type in ("domain", "onion", "sha256", "sha1", "md5", "ssl_sha1"):
        v = v.lower().strip(".")
    if ioc_type == "domain" and v.startswith("www.") and v.count(".") >= 2:
        v = v[4:]
    if ioc_type == "cve":
        v = v.upper()
    return v


def is_valid(value: str, ioc_type: str, defanged: bool = True) -> bool:
    if ioc_type == "ip":
        return valid_ip(value)
    if ioc_type == "cidr":
        return valid_cidr(value)
    if ioc_type in ("domain", "onion"):
        return valid_domain(value, defanged=defanged)
    if ioc_type in ("sha256", "sha1", "md5", "ssl_sha1"):
        return len(set(value)) > 4  # drop 000…0 / aaaa… placeholders
    return True


# ---------------------------------------------------------------- extraction
@dataclass
class Extracted:
    ips: set[str] = field(default_factory=set)
    domains: set[str] = field(default_factory=set)
    sha256: set[str] = field(default_factory=set)
    sha1: set[str] = field(default_factory=set)
    md5: set[str] = field(default_factory=set)

    def items(self):
        onions = {d for d in self.domains if d.endswith(".onion")}
        for t, s in (("ip", self.ips), ("onion", onions), ("domain", self.domains - onions), ("sha256", self.sha256),
                     ("sha1", self.sha1), ("md5", self.md5)):
            for v in sorted(s):
                yield t, v

    def __len__(self):
        return sum(1 for _ in self.items())


def extract(text: str, require_defang: bool = False, hash_types=("sha256", "sha1", "md5")) -> Extracted:
    """Pull IOCs out of free text.

    require_defang=True (used for blog articles) only accepts network IOCs that the author
    defanged (1.2.3[.]4, evil[.]com, hxxp://) — researchers defang real IOCs, while benign
    hostnames/versions in prose are left alone. Hashes are always accepted.
    """
    out = Extracted()
    defanged_tokens = set()
    for tok in re.split(r"[\s<>\"'`|,;]+", text):
        if _DEFANG_MARK.search(tok):
            defanged_tokens.add(refang(tok))
    clean = refang(text)

    network_sources = [" ".join(defanged_tokens)] if require_defang else [clean]
    for src in network_sources:
        for m in URL_RE.findall(src):
            h = host_of(m)
            if h and IPV4_RE.fullmatch(h):
                if valid_ip(h):
                    out.ips.add(h)
            elif h and valid_domain(h, defanged=True):
                out.domains.add(h)
        for m in IPV4_RE.findall(src):
            if valid_ip(m):
                out.ips.add(m)
        for m in DOMAIN_RE.findall(src):
            d = m.lower().strip(".")
            if IPV4_RE.fullmatch(d):
                continue
            if valid_domain(d, defanged=require_defang):
                out.domains.add(d)

    lower = clean.lower()
    if "sha256" in hash_types:
        out.sha256 = {h for h in SHA256_RE.findall(lower) if is_valid(h, "sha256")}
    if "sha1" in hash_types:
        out.sha1 = {h for h in SHA1_RE.findall(lower) if is_valid(h, "sha1")}
    if "md5" in hash_types:
        out.md5 = {h for h in MD5_RE.findall(lower) if is_valid(h, "md5")}
    return out


def strip_html(html: str) -> str:
    html = re.sub(r"(?is)<(script|style|noscript|svg|nav|footer|header)\b.*?</\1>", " ", html)
    html = re.sub(r"(?i)<br\s*/?>|</(p|div|li|tr|h\d|pre|td)>", "\n", html)
    html = re.sub(r"(?s)<[^>]+>", " ", html)
    import html as _h
    return re.sub(r"[ \t\r\f\v]+", " ", _h.unescape(html))
