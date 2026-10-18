import ipaddress
import re
from urllib.parse import unquote, urlparse

from .models import Finding, Result
from .rules import (
    ALL_OFFICIAL,
    LOOKALIKE_MAP,
    OFFICIAL_DOMAINS,
    POINTS,
    RISKY_EXTENSIONS,
    RULES,
    SENSITIVE_WORDS,
    SUSPICIOUS_TLDS,
    TWO_PART_SUFFIXES,
    URL_SHORTENERS,
)


TITLES = {r["key"]: r["title"] for r in RULES}


def refang(text: str) -> str:
    cleaned = text.strip().strip("<>\"' ")
    cleaned = re.sub(r"\bhxxp", "http", cleaned, flags=re.IGNORECASE)
    for fake, real in (("[.]", "."), ("(.)", "."), ("[:]", ":"), ("[dot]", ".")):
        cleaned = cleaned.replace(fake, real)
    return cleaned


def registered_domain(host: str) -> str:
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    if ".".join(parts[-2:]) in TWO_PART_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _is_ip(host: str) -> bool:
    if host.isdigit():
        return True
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _tokens(text: str):
    return [t for t in re.split(r"[.\-_]", text) if t]


def _mentions(tokens, brand: str) -> bool:
    for token in tokens:
        if token == brand or token.startswith(brand):
            return True
        if len(brand) >= 6 and token.endswith(brand):
            return True
    return False


def analyze_url(url: str) -> Result:
    cleaned = refang(url)
    result = Result(kind="url", subject=cleaned)
    if not cleaned:
        return result

    def add(key: str, detail: str = ""):
        result.findings.append(Finding(POINTS[key], TITLES[key], detail))

    if re.match(r"^(javascript|data|vbscript):", cleaned, re.IGNORECASE):
        add("dangerous_scheme", detail="The link does not point to a website.")
        return result

    has_scheme = re.match(r"^[a-z][a-z0-9+.\-]*://", cleaned, re.IGNORECASE) is not None
    try:
        parsed = urlparse(cleaned if has_scheme else "http://" + cleaned)
        host = (parsed.hostname or "").lower().rstrip(".")
        port = parsed.port
    except ValueError:
        host, port, parsed = "", None, None

    if not host:
        add("malformed", detail="No clear domain name could be found in this link.")
        return result

    reg = registered_domain(host)
    tld = host.rsplit(".", 1)[-1]
    is_ip = _is_ip(host)
    path = unquote(parsed.path or "").lower()
    lowered = (host + path + (parsed.query or "")).lower()

    if is_ip:
        add("ip_host", detail=f"The address uses {host} instead of a name.")

    if "@" in cleaned:
        add("at_symbol", detail="Everything before the @ is ignored by the browser.")

    if has_scheme and parsed.scheme == "http":
        add("no_https", detail="The link starts with http://, not https://.")

    if len(cleaned) > 75:
        add("long_url", detail=f"The link is {len(cleaned)} characters long.")

    if not is_ip:
        extra = len(host.split(".")) - len(reg.split("."))
        if extra >= 3:
            add("many_subdomains", detail=f"The real domain here is {reg}.")

    host_tokens = _tokens(host)
    norm_tokens = _tokens(host.translate(LOOKALIKE_MAP))
    for brand, officials in OFFICIAL_DOMAINS.items():
        if reg in officials:
            continue
        if _mentions(host_tokens, brand):
            add("brand_mismatch",
                detail=f"It mentions '{brand}' but the real domain is {reg}.")
            break
        if _mentions(norm_tokens, brand):
            add("lookalike",
                detail=f"{host} imitates '{brand}' by swapping characters.")
            break
    else:
        for brand, officials in OFFICIAL_DOMAINS.items():
            if reg not in officials and brand in path and not _mentions(host_tokens, brand):
                add("brand_in_path",
                    detail=f"'{brand}' appears after the slash, but the site is {reg}.")
                break

    if "xn--" in host:
        add("punycode")
    if any(ord(ch) > 127 for ch in host):
        add("unicode_host")

    if tld in SUSPICIOUS_TLDS:
        add("bad_tld", detail=f"The domain ends in .{tld}.")

    if reg in URL_SHORTENERS:
        add("shortener", detail=f"{reg} is a link-shortening service.")

    if host.count("-") >= 3:
        add("many_hyphens")

    first_label = host.split(".")[0]
    if not is_ip and sum(ch.isdigit() for ch in first_label) >= 4:
        add("many_digits")

    if port and port not in (80, 443):
        add("odd_port", detail=f"The link uses port {port}.")

    if path.endswith(RISKY_EXTENSIONS):
        add("risky_download", detail="The link points straight to a program file.")

    query = (parsed.query or "").lower()
    if re.search(r"(?:^|&)[a-z_]*(?:url|redirect|next|continue|return|dest|goto)"
                 r"[a-z_]*=(?:https?(?::|%3a)|//|%2f%2f)", query):
        add("redirect_param")

    if reg not in ALL_OFFICIAL:
        hits = [w for w in SENSITIVE_WORDS if w in lowered]
        if hits:
            add("sensitive_words", detail="Found: " + ", ".join(hits[:4]) + ".")

    return result
