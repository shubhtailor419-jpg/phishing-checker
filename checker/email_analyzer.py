import re

from .models import Finding, Result
from .rules import (
    BAIT_PATTERN,
    CREDENTIAL_PATTERN,
    GREETING_PATTERN,
    LINK_CAP,
    MAX_LINKS_ANALYSED,
    URGENCY_BASE,
    URGENCY_MAX,
    URGENCY_STEP,
    URGENCY_PATTERN,
)
from .url_analyzer import analyze_url

LINK_PATTERN = re.compile(r"(?:https?://|www\.)[^\s<>\"')\]]+", re.IGNORECASE)


def _unique_matches(pattern, text):
    seen = []
    for match in pattern.finditer(text):
        word = match.group(0).lower()
        if word not in seen:
            seen.append(word)
    return seen


def _shorten(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def analyze_email(text: str) -> Result:
    text = text.strip()
    preview = _shorten(" ".join(text.split()), 80)
    result = Result(kind="email", subject=preview)
    if not text:
        return result

    urgency = _unique_matches(URGENCY_PATTERN, text)
    if urgency:
        points = min(URGENCY_MAX, URGENCY_BASE + URGENCY_STEP * (len(urgency) - 1))
        result.findings.append(Finding(
            points, "Pressure and urgency",
            "Phrases found: " + ", ".join(urgency[:4]) + "."))

    creds = _unique_matches(CREDENTIAL_PATTERN, text)
    if creds:
        result.findings.append(Finding(
            20, "Asks for sensitive information",
            "Mentions: " + ", ".join(creds[:4]) + "."))

    bait = _unique_matches(BAIT_PATTERN, text)
    if bait:
        result.findings.append(Finding(
            15, "Threats or rewards",
            "Phrases found: " + ", ".join(bait[:4]) + "."))

    if GREETING_PATTERN.search(text):
        result.findings.append(Finding(
            5, "Generic greeting", "It does not address you by name."))

    links = []
    for raw in LINK_PATTERN.findall(text):
        link = raw.rstrip(".,;:!?")
        if link not in links:
            links.append(link)
    links = links[:MAX_LINKS_ANALYSED]

    worst = 0
    link_notes = []
    for link in links:
        sub = analyze_url(link)
        if sub.score > 0:
            worst = max(worst, sub.score)
            for finding in sub.findings:
                link_notes.append(Finding(
                    0, "Link: " + finding.title,
                    _shorten(link, 60) + " — " + finding.detail))

    if worst:
        result.findings.append(Finding(
            min(LINK_CAP, worst), "Risky link inside the message",
            f"The riskiest link scored {worst}/100 on its own."))
        result.findings.extend(link_notes)
    elif links:
        result.findings.append(Finding(
            0, f"{len(links)} link(s) found",
            "None of them showed strong red flags on their own."))

    return result
