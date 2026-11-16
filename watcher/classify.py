"""Map malware tags / article text to a target vault page using config/mapping.yml."""
from __future__ import annotations

import re
from dataclasses import dataclass

_SUFFIXES = ("stealer", "ransomware", "ransom", "loader", "botnet", "bot", "rat", "backdoor",
             "trojan", "banker", "wiper", "group", "team", "malware", "apt")
_PREFIX = re.compile(r"^(win|elf|osx|apk|js|ps1|jar|vbs|py)\.", re.I)


def norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", s.lower())


@dataclass
class Target:
    path: str
    title: str
    aliases: list[str]
    strict: list[str]          # case-sensitive, whole-word, title/tag-only aliases
    category: str


class Classifier:
    def __init__(self, mapping: dict):
        self.targets = [Target(t["path"], t["title"], t.get("aliases", []), t.get("strict", []),
                               t.get("category", "")) for t in mapping.get("targets", [])]
        self._tag_idx: dict[str, Target] = {}
        self._text_rx: list[tuple[Target, re.Pattern, re.Pattern | None]] = []
        for t in self.targets:
            for a in t.aliases + t.strict:
                n = norm(a)
                if len(n) < 3:
                    continue
                self._tag_idx.setdefault(n, t)
                for suf in _SUFFIXES:
                    if n.endswith(suf) and len(n) - len(suf) >= 5:
                        self._tag_idx.setdefault(n[: -len(suf)], t)
            loose = [re.escape(a).replace(r"\ ", r"[\s_-]?") for a in t.aliases if len(norm(a)) >= 4]
            strict = [re.escape(a) for a in t.strict]
            rx = re.compile(r"(?<![\w-])(?:" + "|".join(loose) + r")(?![\w-])", re.I) if loose else None
            srx = re.compile(r"(?<![\w-])(?:" + "|".join(strict) + r")(?![\w-])") if strict else None
            self._text_rx.append((t, rx, srx))

    # -- structured feeds (ThreatFox malware name, Feodo family, MB signature, tags)
    def from_tags(self, *tags) -> Target | None:
        for tag in tags:
            if not tag:
                continue
            for piece in re.split(r"[,;|]", str(tag)):
                n = norm(_PREFIX.sub("", piece.strip()))
                if len(n) < 3:
                    continue
                if n in self._tag_idx:
                    return self._tag_idx[n]
                for suf in _SUFFIXES:
                    if n.endswith(suf) and n[: -len(suf)] in self._tag_idx and len(n) - len(suf) >= 4:
                        return self._tag_idx[n[: -len(suf)]]
        return None

    # -- free text (blog articles, repo file paths)
    def from_text(self, title: str, body: str = "", min_score: int = 3) -> list[tuple[Target, int]]:
        hits = []
        for t, rx, srx in self._text_rx:
            score = 0
            if rx:
                score += 5 * len(rx.findall(title)) + len(rx.findall(body))
            if srx:
                score += 5 * len(srx.findall(title))
            if score >= min_score:
                hits.append((t, score))
        hits.sort(key=lambda x: -x[1])
        return hits
