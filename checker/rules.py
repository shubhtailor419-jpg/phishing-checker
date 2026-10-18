import re

RULES = [
    {"key": "dangerous_scheme", "kind": "url", "points": 60,
     "title": "Script or data link",
     "why": "Links starting with javascript: or data: run code or show content "
            "inside your browser instead of opening a normal website."},
    {"key": "malformed", "kind": "url", "points": 30,
     "title": "Malformed link",
     "why": "The address has no clear domain name, which normal links always have."},
    {"key": "ip_host", "kind": "url", "points": 30,
     "title": "IP address instead of a domain",
     "why": "Real companies use names like paypal.com. Raw IP addresses are a "
            "classic way to hide who owns a site."},
    {"key": "brand_mismatch", "kind": "url", "points": 30,
     "title": "Brand name on the wrong domain",
     "why": "A link such as paypal-login.example.top mentions a brand but "
            "belongs to someone else. Only the real domain counts."},
    {"key": "lookalike", "kind": "url", "points": 30,
     "title": "Look-alike spelling",
     "why": "Swapping letters for digits (paypa1, g00gle) imitates a brand "
            "while passing a quick glance."},
    {"key": "shortener", "kind": "url", "points": 25,
     "title": "Shortened link",
     "why": "Link shorteners hide the real destination. Expand it with a "
            "preview tool before trusting it."},
    {"key": "at_symbol", "kind": "url", "points": 20,
     "title": "'@' symbol in the address",
     "why": "Browsers ignore everything before an @, so attackers put a "
            "trusted-looking name there to hide the real host."},
    {"key": "punycode", "kind": "url", "points": 25,
     "title": "Punycode domain (xn--)",
     "why": "Punycode lets letters from other alphabets stand in for look-alike "
            "English letters."},
    {"key": "unicode_host", "kind": "url", "points": 25,
     "title": "Non-ASCII characters in the domain",
     "why": "Characters from other alphabets can look identical to English "
            "letters (for example a Cyrillic 'a')."},
    {"key": "risky_download", "kind": "url", "points": 25,
     "title": "Link to a program download",
     "why": "Links ending in .apk, .exe and similar files install software. "
            "Scam messages often push fake apps this way."},
    {"key": "many_subdomains", "kind": "url", "points": 15,
     "title": "Too many subdomains",
     "why": "In login.paypal.com.example.top the real domain is the LAST part "
            "(example.top), not the brand at the start."},
    {"key": "bad_tld", "kind": "url", "points": 15,
     "title": "Domain ending often used in scams",
     "why": "Some cheap endings such as .top, .xyz and .icu are heavily used "
            "for throwaway attack sites."},
    {"key": "no_https", "kind": "url", "points": 10,
     "title": "No HTTPS",
     "why": "The connection is not encrypted. HTTPS alone does not prove a site "
            "is safe, but missing it on a login page is a warning sign."},
    {"key": "long_url", "kind": "url", "points": 10,
     "title": "Very long address",
     "why": "Long addresses can bury the real destination in the middle."},
    {"key": "many_hyphens", "kind": "url", "points": 10,
     "title": "Many hyphens in the domain",
     "why": "Names like secure-login-update-account.com are typical of "
            "generated phishing domains."},
    {"key": "many_digits", "kind": "url", "points": 10,
     "title": "Many digits in the domain",
     "why": "Random-looking numbers in a domain are common in automatically "
            "generated sites."},
    {"key": "odd_port", "kind": "url", "points": 10,
     "title": "Unusual port number",
     "why": "Normal websites use the standard ports 80 and 443."},
    {"key": "sensitive_words", "kind": "url", "points": 10,
     "title": "Login-style words on an unknown site",
     "why": "Words like login, verify and update on a domain that is not a "
            "known official one often mean a fake sign-in page."},
    {"key": "redirect_param", "kind": "url", "points": 10,
     "title": "Another link hidden inside the link",
     "why": "A parameter such as ?url=http://... can bounce you to a different "
            "site than the one you see first."},
    {"key": "brand_in_path", "kind": "url", "points": 10,
     "title": "Brand name only in the path",
     "why": "Putting 'paypal' after the slash does not make a site PayPal's."},
    {"key": "urgency", "kind": "email", "points": "+10 to +25",
     "title": "Pressure and urgency",
     "why": "Phishing tries to make you act before you think: 'act now', "
            "'account suspended', 'within 24 hours'."},
    {"key": "credentials", "kind": "email", "points": 20,
     "title": "Asks for sensitive information",
     "why": "Banks and companies never ask for your password, OTP, PIN or CVV "
            "by email, SMS or WhatsApp."},
    {"key": "bait", "kind": "email", "points": 15,
     "title": "Threats or rewards",
     "why": "Fake prizes, refunds and legal threats are used to push people "
            "into clicking."},
    {"key": "greeting", "kind": "email", "points": 5,
     "title": "Generic greeting",
     "why": "'Dear customer' suggests a bulk message, not one from a company "
            "that knows your name."},
    {"key": "risky_link", "kind": "email", "points": "up to +60",
     "title": "Risky link inside the message",
     "why": "Every link in the message is checked with the URL rules above. "
            "The riskiest one counts."},
]

POINTS = {r["key"]: r["points"] for r in RULES if isinstance(r["points"], int)}

URGENCY_BASE = 10
URGENCY_STEP = 5
URGENCY_MAX = 25
LINK_CAP = 60
MAX_LINKS_ANALYSED = 10


OFFICIAL_DOMAINS = {
    "paypal": {"paypal.com"},
    "google": {"google.com", "google.co.in", "googleusercontent.com",
               "googleapis.com", "gstatic.com"},
    "amazon": {"amazon.com", "amazon.in", "amazonaws.com"},
    "microsoft": {"microsoft.com", "live.com", "office.com"},
    "apple": {"apple.com", "icloud.com"},
    "facebook": {"facebook.com"},
    "instagram": {"instagram.com"},
    "whatsapp": {"whatsapp.com"},
    "netflix": {"netflix.com"},
    "flipkart": {"flipkart.com"},
    "paytm": {"paytm.com"},
    "phonepe": {"phonepe.com"},
    "irctc": {"irctc.co.in"},
    "sbi": {"sbi.co.in", "onlinesbi.sbi", "onlinesbi.com", "sbicard.com"},
    "hdfc": {"hdfcbank.com"},
    "icici": {"icicibank.com"},
}
ALL_OFFICIAL = set().union(*OFFICIAL_DOMAINS.values())

SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "link", "zip",
    "country", "loan", "rest", "icu", "buzz", "cyou", "monster", "sbs", "cfd",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at",
}

TWO_PART_SUFFIXES = {
    "co.in", "org.in", "net.in", "gov.in", "ac.in", "co.uk",
    "com.au", "com.br", "co.jp",
}

SENSITIVE_WORDS = [
    "login", "signin", "verify", "secure", "update", "account",
    "password", "bank", "wallet", "confirm",
]

RISKY_EXTENSIONS = (".apk", ".exe", ".scr", ".msi", ".bat", ".jar", ".vbs")

LOOKALIKE_MAP = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s"})


def word_pattern(words):
    escaped = (re.escape(w) for w in words)
    return re.compile(r"\b(?:" + "|".join(escaped) + r")\b", re.IGNORECASE)


URGENCY_PATTERN = word_pattern([
    "urgent", "urgently", "immediately", "act now", "within 24 hours",
    "final notice", "account suspended", "account will be closed",
    "limited time", "verify now", "expires today", "last warning",
])

CREDENTIAL_PATTERN = word_pattern([
    "password", "otp", "one time password", "card number", "cvv", "pin",
    "net banking", "confirm your identity", "login details", "aadhaar",
])

BAIT_PATTERN = word_pattern([
    "you have won", "lottery", "prize", "claim your reward", "gift card",
    "refund", "unusual activity", "unauthorized", "legal action", "kyc",
    "parcel", "customs", "sim will be blocked",
    "electricity will be disconnected", "pan card",
])

GREETING_PATTERN = re.compile(
    r"\bdear (customer|user|member|account holder|sir|madam|client)\b",
    re.IGNORECASE,
)
