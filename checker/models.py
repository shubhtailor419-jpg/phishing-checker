from dataclasses import dataclass, field

LOW_MAX = 20
MEDIUM_MAX = 50

VERDICTS = {
    "low": "Low risk",
    "medium": "Suspicious",
    "high": "Likely phishing",
}

ADVICE = {
    "low": (
        "No strong red flags were found, but no tool can prove something is "
        "safe. If the message pushed you to act quickly, double-check through "
        "the official app or website."
    ),
    "medium": (
        "There are several warning signs. Don't enter passwords, OTPs or card "
        "details. Open the official website or app yourself instead of using "
        "this link."
    ),
    "high": (
        "Strong signs of phishing. Do not click, reply or enter any details. "
        "If you already did, change your passwords, call your bank, and report "
        "it at cybercrime.gov.in or on 1930 (India)."
    ),
}


@dataclass(frozen=True)
class Finding:
    points: int
    title: str
    detail: str = ""

    @property
    def severity(self) -> str:
        if self.points >= 25:
            return "high"
        if self.points >= 15:
            return "medium"
        if self.points > 0:
            return "low"
        return "info"

    def to_dict(self) -> dict:
        return {
            "points": self.points,
            "title": self.title,
            "detail": self.detail,
            "severity": self.severity,
        }


@dataclass
class Result:
    kind: str
    subject: str
    findings: list = field(default_factory=list)

    @property
    def score(self) -> int:
        return min(100, sum(f.points for f in self.findings))

    @property
    def level(self) -> str:
        score = self.score
        if score <= LOW_MAX:
            return "low"
        if score <= MEDIUM_MAX:
            return "medium"
        return "high"

    @property
    def verdict(self) -> str:
        return VERDICTS[self.level]

    @property
    def advice(self) -> str:
        return ADVICE[self.level]

    def to_dict(self) -> dict:
        ordered = sorted(self.findings, key=lambda f: -f.points)
        return {
            "kind": self.kind,
            "subject": self.subject,
            "score": self.score,
            "level": self.level,
            "verdict": self.verdict,
            "advice": self.advice,
            "findings": [f.to_dict() for f in ordered],
        }
