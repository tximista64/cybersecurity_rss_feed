#!/usr/bin/env python3
"""
cyber_watch.py — Daily cyber threat intelligence digest via Claude Code

Usage:
    # Local source
    python cyber_watch.py --feeds urls.md | claude

    # Remote source (GitHub)
    python cyber_watch.py --feeds-url https://raw.githubusercontent.com/tximista64/cybersecurity_rss_feed/main/urls.md | claude

    # With thematic scoring
    python cyber_watch.py --feeds urls.md --scored | claude

    # Export markdown directly
    python cyber_watch.py --feeds urls.md --scored | claude > veille_$(date +%Y%m%d).md

    # Limit time window
    python cyber_watch.py --feeds urls.md --max-age 24 | claude

    # Filter by profile (pentest | blueteam | geopo | all)
    python cyber_watch.py --feeds urls.md --profile pentest --scored | claude
    python cyber_watch.py --feeds-url https://raw.githubusercontent.com/tximista64/cybersecurity_rss_feed/main/urls.md --profile geopo | claude

Dependencies:
    pip install feedparser
    (anthropic not required — Claude Code handles the LLM)
"""

import argparse
import re
import sys
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

try:
    import feedparser
except ImportError:
    print("[!] feedparser missing: pip install feedparser", file=sys.stderr)
    sys.exit(1)

# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────

MAX_ARTICLES   = 100
MAX_PER_FEED   = 3
MAX_AGE_HOURS  = 48
MAX_DESC_CHARS = 600

THEMES = {
    "CVE / Vulnerabilities":  ["CVE-", "vuln", "patch", "exploit", "RCE", "LPE", "bypass", "0day", "zero-day"],
    "APT / Threat Actors":    ["APT", "threat actor", "nation-state", "campaign", "TTPs", "attribution"],
    "Pentest / Red Team":     ["pentest", "red team", "post-exploitation", "privesc", "lateral movement",
                               "evasion", "shellcode", "OSCP", "C2", "implant", "payload", "persistence"],
    "Bug Bounty":             ["bug bounty", "bounty", "writeup", "disclosure", "SSRF", "IDOR",
                               "injection", "recon", "HackerOne", "Bugcrowd", "Intigriti", "YesWeHack"],
    "Offensive Tools":        ["tool", "framework", "POC", "PoC", "malware", "RAT", "nuclei", "scanner"],
    "Defense / Blue Team":    ["detection", "SIEM", "EDR", "SOC", "blue team", "hunting", "Sigma", "YARA"],
    "Ransomware / Cybercrime":["ransomware", "extortion", "leak", "darkweb", "group", "gang"],
    "Geopolitics / Intel":    ["geopolitics", "géopolitique", "renseignement", "espionnage", "NATO", "OTAN",
                               "guerre", "war", "conflit", "sanctions", "Chine", "Russie", "Iran", "OSINT"],
    "Misc":                   [],
}

PROFILES = {
    "pentest":  ["Offensive", "Bug Bounty", "CTF", "Persons of Interest"],
    "blueteam": ["Blueteam", "Conf", "Persons of Interest"],
    "geopo":    ["Osint", "Geopo", "Podcasts"],
    "all":      None,
}

# ─────────────────────────────────────────────
# FEED LOADING
# ─────────────────────────────────────────────

def load_feeds(path: str = None, url: str = None, profile: str = "all") -> list[str]:
    sections_filter = PROFILES.get(profile)
    if url:
        with urllib.request.urlopen(url) as r:
            content = r.read().decode("utf-8")
    else:
        content = Path(path).read_text(encoding="utf-8")
    urls = []
    current_section = ""
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("#"):
            current_section = stripped.replace("#", "").strip()
            continue
        if sections_filter is not None:
            if not any(f.lower() in current_section.lower() for f in sections_filter):
                continue
        md = re.search(r'\(https?://[^\)]+\)', stripped)
        if md:
            urls.append(md.group()[1:-1])
        elif stripped.startswith("http"):
            urls.append(stripped)
    return list(dict.fromkeys(urls))

# ─────────────────────────────────────────────
# FETCH & PARSE
# ─────────────────────────────────────────────

def is_recent(entry, max_age_hours: int) -> bool:
    for attr in ("published_parsed", "updated_parsed"):
        t = getattr(entry, attr, None)
        if t:
            pub = datetime(*t[:6], tzinfo=timezone.utc)
            return datetime.now(timezone.utc) - pub < timedelta(hours=max_age_hours)
    return True


def fetch_articles(feed_urls: list[str], max_age_hours: int) -> list[dict]:
    articles = []
    for url in feed_urls:
        try:
            feed = feedparser.parse(url, request_headers={"User-Agent": "cyber-watch/1.0"})
            source = feed.feed.get("title", url)
            count = 0
            for entry in feed.entries:
                if count >= MAX_PER_FEED:
                    break
                if not is_recent(entry, max_age_hours):
                    continue
                title = entry.get("title", "Sans titre")
                desc  = re.sub(r"<[^>]+>", "", entry.get("summary", entry.get("description", "")))
                desc  = desc[:MAX_DESC_CHARS]
                link  = entry.get("link", "")
                articles.append({"source": source, "title": title, "desc": desc, "link": link})
                count += 1
        except Exception as e:
            print(f"  [!] Feed skipped ({url}): {e}", file=sys.stderr)
    return articles[:MAX_ARTICLES]

# ─────────────────────────────────────────────
# SCORING
# ─────────────────────────────────────────────

def score_article(title: str, desc: str) -> str:
    text = (title + " " + desc).lower()
    for theme, keywords in THEMES.items():
        if theme == "Misc":
            continue
        if any(k.lower() in text for k in keywords):
            return theme
    return "Misc"

# ─────────────────────────────────────────────
# PROMPT BUILDER
# ─────────────────────────────────────────────

def build_prompt(articles: list[dict], scored: bool) -> str:
    date_str = datetime.now().strftime("%d/%m/%Y")

    articles_txt = ""
    for i, a in enumerate(articles, 1):
        theme_tag = f"[{score_article(a['title'], a['desc'])}] " if scored else ""
        articles_txt += (
            f"\n---\n"
            f"[{i}] {theme_tag}{a['source']}\n"
            f"Titre : {a['title']}\n"
            f"Résumé : {a['desc']}\n"
            f"Lien : {a['link']}\n"
        )

    mode = (
        "Group articles by theme in this priority order: "
        "CVE/Vulnerabilities, APT/Threat Actors, Pentest/Red Team, Bug Bounty, Offensive Tools, "
        "Defense/Blue Team, Ransomware/Cybercrime, Geopolitics/Intel, Misc. "
        "Assign a criticality level (🔴 Critical / 🟠 High / 🟡 Medium / 🟢 Info) to each article."
        if scored else
        "Present articles in reverse chronological order, most recent first."
    )

    return f"""You are a senior CTI analyst. Generate a daily cyber threat intelligence digest for {date_str}.

INSTRUCTIONS:
- Process ALL provided articles without exception, including geopolitical, strategic, or general context articles.
- {mode}
- For each article: title, source, criticality if scoring is enabled, 2-3 sentence summary, link.
- Style: concise, factual, SOC/DFIR practitioner-oriented.
- Format: structured Markdown, Obsidian-ready.
- Header: # Cyber Watch — {date_str}
- Footer: number of articles processed, number of sources covered.
- Reply ONLY with the digest markdown, no introduction or commentary.

ARTICLES:
{articles_txt}
"""

# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Prepare the daily cyber threat intelligence prompt for Claude Code",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    feeds_group = parser.add_mutually_exclusive_group(required=True)
    feeds_group.add_argument("--feeds", metavar="FILE",
                        help="Local .md file containing feed URLs")
    feeds_group.add_argument("--feeds-url", metavar="URL",
                        help="Remote feed file URL (e.g. raw GitHub)")
    parser.add_argument("--scored",  action="store_true",
                        help="Enable thematic scoring and criticality levels")
    parser.add_argument("--max-age", type=int, default=MAX_AGE_HOURS, metavar="H",
                        help=f"Maximum article age in hours (default: {MAX_AGE_HOURS})")
    parser.add_argument("--profile", choices=list(PROFILES), default="all", metavar="PROFILE",
                        help=f"Filter by profile: {', '.join(PROFILES)} (default: all)")
    args = parser.parse_args()

    print(f"⟳ Loading feeds [profile: {args.profile}]...", file=sys.stderr)
    feed_urls = load_feeds(path=args.feeds, url=args.feeds_url, profile=args.profile)
    if not feed_urls:
        print("[!] No URLs found.", file=sys.stderr)
        sys.exit(1)
    print(f"  → {len(feed_urls)} feeds loaded", file=sys.stderr)

    print(f"⟳ Fetching articles (< {args.max_age}h)...", file=sys.stderr)
    articles = fetch_articles(feed_urls, args.max_age)
    if not articles:
        print("[!] No recent articles found.", file=sys.stderr)
        sys.exit(1)
    print(f"  → {len(articles)} recent articles", file=sys.stderr)

    mode_label = "scored" if args.scored else "chronological"
    print(f"⟳ Prompt ready ({mode_label} / profile: {args.profile}), piping to Claude Code...", file=sys.stderr)
    print(build_prompt(articles, args.scored))


if __name__ == "__main__":
    main()
