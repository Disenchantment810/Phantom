"""Pattern-based security log analysis (PRD §3.4, FR-07).

Input contract:
- Bounded plain text (paste or upload). Logs are data only — never executed,
  never sent anywhere by default.
- Any text is accepted; line formats that parse as one of the supported
  schemas (syslog-style, auth.log, SSH lines, generic key=value) are
  structured into timestamp / host / process / source IP / username / result.
  Lines that do not parse are still scanned by content rules.

Interpretation stance (PRD §10):
- Flagged patterns are **indicators for review, not proof of compromise**.
  Every finding repeats that in plain language.
- IP addresses and usernames are processed in memory only and shown only in
  the rendered result; no raw log text is stored by PHANTOM.

Privacy:
- Before analysis, values that look like secrets (tokens, passwords in
  key=value pairs, Basic-auth headers) are masked in every output the user
  sees and in anything that would be submitted to an AI provider (Phase 4).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime

from app.models import Confidence, FindingSource, Severity

MAX_CONTENT_CHARS = 524_288
MAX_LINES = 50_000
MAX_FINDINGS = 100
FAILED_THRESHOLD = 5  # failed attempts within the window
FAILED_WINDOW_SECONDS = 300  # 5 minutes
SUCCESS_AFTER_FAILURES = 3  # successes that quickly follow failures
SUCCESS_MAX_WINDOW_SECONDS = 3600  # "shortly after" = within one hour

TIMESTAMP_FORMATS = (
    "%b %d %H:%M:%S",  # syslog: Oct 15 12:34:56
    "%b %e %H:%M:%S",  # syslog, space-padded day
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
    "%d/%b/%Y:%H:%M:%S",
)

# value-capturing groups: ip, user, result
LINE_PATTERNS: tuple[tuple[str, re.Pattern], ...] = (
    (
        # syslog/auth.log: "Oct 15 12:34:56 host sshd[123]: Failed password for root from 1.2.3.4 port 22 ssh2"
        "syslog",
        re.compile(
            r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
            r"(?P<host>\S+)\s+(?P<process>[\w\-.]+)(?:\[\d+\])?:\s+"
            r"(?P<message>.*)$"
        ),
    ),
    (
        # "2026-10-15 12:34:56,123 INFO process: message"
        "python-logging",
        re.compile(
            r"^(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?)\s+"
            r"(?P<level>[A-Z]+)\s+(?P<process>[\w\-.]+)\s*:?\s+(?P<message>.*)$"
        ),
    ),
    (
        # generic: "2026-10-15T12:34:56 process: message"
        "iso",
        re.compile(
            r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
            r"(?P<process>[\w\-.]+)(?:\[\d+\])?:?\s+(?P<message>.*)$"
        ),
    ),
)

MESSAGE_PATTERNS = {
    "ip": re.compile(r"\b(?P<ip>(?:\d{1,3}\.){3}\d{1,3})\b"),
    "failed": re.compile(
        r"\b(?:failed|invalid user|authentication failure|auth failure|"
        r"password mismatch|login failed|connection closed by authenticating user)\b",
        re.IGNORECASE,
    ),
    "success": re.compile(
        r"\b(?:accepted|session opened|login successful|authenticated successfully|"
        r"successful login|password accepted)\b",
        re.IGNORECASE,
    ),
    "user": re.compile(
        r"\b(?:for (?:invalid user )?|user(?:name)?[ =])"
        r"(?P<user>[A-Za-z0-9_.@$-]{1,64})",
        re.IGNORECASE,
    ),
    "port": re.compile(r"\bport\s+(\d{1,5})\b", re.IGNORECASE),
}

# Secrets that must be masked everywhere they would be echoed. Order matters:
# longer, structured patterns first so e.g. "Authorization: Bearer x" is
# fully masked by one pass instead of being split across two.
SECRET_PATTERNS: tuple[re.Pattern, ...] = (
    re.compile(r"(?i)\b(?P<scheme>basic|bearer)\s+(?P<value>[A-Za-z0-9._+/=-]{8,})"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(
        r"(?i)\b(?P<key>password|passwd|pwd|secret|token|api[_-]?key|authorization)(?P<sep>\s*[:=]\s*)(?P<value>\S+)"
    ),
)


class LogAnalysisError(ValueError):
    """Input failed validation; safe to show the reason to the user."""


@dataclass(frozen=True)
class ParsedLine:
    line_number: int
    timestamp: datetime | None
    raw_timestamp: str
    process: str
    message: str
    source_ip: str | None
    username: str | None
    outcome: str  # "failed", "success", or "other"
    matched_format: str


@dataclass(frozen=True)
class LogFinding:
    title: str
    category: str
    severity: Severity
    confidence: Confidence
    line_start: int
    line_end: int
    evidence: str
    explanation: str
    recommendation: str
    rule_id: str
    source_type: FindingSource = FindingSource.RULE

    @property
    def location_label(self) -> str:
        if self.line_start == self.line_end:
            return f"Line {self.line_start}"
        return f"Lines {self.line_start}–{self.line_end}"


@dataclass
class LogStats:
    total_lines: int = 0
    parsed_lines: int = 0
    failed_events: int = 0
    success_events: int = 0
    unique_ips: int = 0
    unique_users: int = 0
    time_span: str | None = None


@dataclass
class LogAnalysisResult:
    findings: list[LogFinding] = field(default_factory=list)
    stats: LogStats = field(default_factory=LogStats)
    sample_parse: dict | None = None  # one structured example, for transparency


def mask_secrets(text: str) -> str:
    """Mask secret-looking values in text shown to the user or sent onward."""
    masked = text
    for pattern in SECRET_PATTERNS:
        masked = pattern.sub(_mask_one, masked)
    return masked


def _mask_one(match: re.Match) -> str:
    groups = match.groupdict()
    if "scheme" in groups and groups["scheme"] is not None:
        return f"{groups['scheme']} [REDACTED]"
    if "key" in groups and groups["key"] is not None:
        return f"{groups['key']}{groups.get('sep', '')}[REDACTED]"
    return "[REDACTED]"


def _parse_timestamp(raw: str) -> datetime | None:
    cleaned = raw.split(",")[0].split(".")[0]
    for fmt in TIMESTAMP_FORMATS:
        try:
            return datetime.strptime(cleaned, fmt)
        except ValueError:
            continue
    return None


def _classify(message: str) -> str:
    if MESSAGE_PATTERNS["failed"].search(message):
        return "failed"
    if MESSAGE_PATTERNS["success"].search(message):
        return "success"
    return "other"


def parse_line(line_number: int, line: str) -> ParsedLine | None:
    """Parse one log line into fields, or None if no schema matches."""
    for format_name, pattern in LINE_PATTERNS:
        match = pattern.match(line)
        if match is None:
            continue
        message = match.group("message")
        ip_match = MESSAGE_PATTERNS["ip"].search(message)
        user_match = MESSAGE_PATTERNS["user"].search(message)
        return ParsedLine(
            line_number=line_number,
            timestamp=_parse_timestamp(match.group("ts")),
            raw_timestamp=match.group("ts"),
            process=match.group("process") or "",
            message=message,
            source_ip=ip_match.group("ip") if ip_match else None,
            username=user_match.group("user") if user_match else None,
            outcome=_classify(message),
            matched_format=format_name,
        )
    return None


def _validate(content: str) -> None:
    if not content or not content.strip():
        raise LogAnalysisError("Paste or upload some log text to analyze.")
    if len(content) > MAX_CONTENT_CHARS:
        raise LogAnalysisError("The log text is too large. Analyze a smaller excerpt.")
    if "\x00" in content:
        raise LogAnalysisError("The file looks binary. PHANTOM reviews text logs only.")
    if content.count("\n") + 1 > MAX_LINES:
        raise LogAnalysisError(f"Too many lines (limit {MAX_LINES:,}). Analyze a smaller excerpt.")


def analyze_log(content: str) -> LogAnalysisResult:
    """Analyze log text and return indicator findings. Pure function over data."""
    _validate(content)
    masked = mask_secrets(content)
    lines = masked.splitlines()

    parsed: list[ParsedLine] = []
    stats = LogStats()
    ips: set[str] = set()
    users: set[str] = set()
    first_ts: datetime | None = None
    last_ts: datetime | None = None
    sample = None

    for number, line in enumerate(lines, start=1):
        stats.total_lines = number
        entry = parse_line(number, line)
        if entry is None:
            continue
        parsed.append(entry)
        if sample is None and entry.message:
            sample = {
                "line": number,
                "format": entry.matched_format,
                "fields": {
                    "timestamp": entry.raw_timestamp,
                    "process": entry.process,
                    "source_ip": entry.source_ip,
                    "username": entry.username,
                    "outcome": entry.outcome,
                },
            }
        stats.parsed_lines += 1
        if entry.source_ip:
            ips.add(entry.source_ip)
        if entry.username:
            users.add(entry.username)
        if entry.outcome == "failed":
            stats.failed_events += 1
        elif entry.outcome == "success":
            stats.success_events += 1
        if entry.timestamp is not None:
            if first_ts is None or entry.timestamp < first_ts:
                first_ts = entry.timestamp
            if last_ts is None or entry.timestamp > last_ts:
                last_ts = entry.timestamp

    stats.unique_ips = len(ips)
    stats.unique_users = len(users)
    if first_ts is not None and last_ts is not None:
        # Syslog stamps carry no year (strptime fills in 1900); display accordingly.
        fmt = "%Y-%m-%d %H:%M:%S" if first_ts.year != 1900 else "%b %d %H:%M:%S"
        stats.time_span = (
            f"{first_ts.strftime(fmt)} – {last_ts.strftime(fmt)}"
        )

    findings = _find_failed_bursts(parsed)
    findings += _find_success_after_failures(parsed)
    findings += _find_secret_leaks(content.splitlines(), masked.splitlines())
    findings.sort(key=lambda f: f.line_start)
    if len(findings) > MAX_FINDINGS:
        findings = findings[:MAX_FINDINGS]

    return LogAnalysisResult(findings=findings, stats=stats, sample_parse=sample)


def _format_window(events: list[ParsedLine]) -> str:
    first = events[0]
    last = events[-1]
    start = first.timestamp.strftime("%H:%M:%S") if first.timestamp else first.raw_timestamp
    end = last.timestamp.strftime("%H:%M:%S") if last.timestamp else last.raw_timestamp
    usernames = sorted({e.username for e in events if e.username})
    user_part = f" targeting {', '.join(usernames[:3])}" + ("…" if len(usernames) > 3 else "") if usernames else ""
    return f"{len(events)} failed attempts between {start} and {end}{user_part}"


def _find_failed_bursts(events: list[ParsedLine]) -> list[LogFinding]:
    """Group failed attempts per source IP inside the time window."""
    findings: list[LogFinding] = []
    by_ip: dict[str, list[ParsedLine]] = {}
    undated: list[ParsedLine] = []
    for event in events:
        if event.outcome != "failed" or event.source_ip is None:
            continue
        by_ip.setdefault(event.source_ip, []).append(event)
        if event.timestamp is None:
            undated.append(event)

    for source_ip, ip_events in by_ip.items():
        # Path A: timestamps available — sliding window per IP.
        dated = [e for e in ip_events if e.timestamp is not None]
        if len(dated) >= FAILED_THRESHOLD:
            dated.sort(key=lambda e: e.timestamp)
            window: list[ParsedLine] = []
            best_window: list[ParsedLine] = []
            for event in dated:
                window.append(event)
                while (
                    (event.timestamp - window[0].timestamp).total_seconds()
                    > FAILED_WINDOW_SECONDS
                ):
                    window.pop(0)
                if len(window) > len(best_window):
                    best_window = list(window)
            if len(best_window) >= FAILED_THRESHOLD:
                findings.append(
                    LogFinding(
                        title="Repeated failed logins from one address",
                        category="authentication",
                        severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        line_start=best_window[0].line_number,
                        line_end=best_window[-1].line_number,
                        evidence=(
                            f"{source_ip}: {_format_window(best_window)} "
                            f"({len(best_window)} failures in {FAILED_WINDOW_SECONDS // 60} minutes)."
                        ),
                        explanation=(
                            "Many failed logins from one address in a short time is the typical "
                            "signature of an automated password-guessing attempt. It is an "
                            "indicator for review, not proof of compromise — failed attempts "
                            "also happen after a legitimate user forgets a password."
                        ),
                        recommendation=(
                            "Review whether these attempts ever succeeded, consider rate-limiting "
                            "or blocking the address, and confirm MFA is enabled for the accounts involved."
                        ),
                        rule_id="LOG-BRUTE-001",
                    )
                )
        # Path B: no timestamps — count-based fallback.
        elif not dated and len(ip_events) >= FAILED_THRESHOLD:
            findings.append(
                LogFinding(
                    title="Repeated failed logins from one address",
                    category="authentication",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.LOW,
                    line_start=ip_events[0].line_number,
                    line_end=ip_events[-1].line_number,
                    evidence=(
                        f"{source_ip}: {len(ip_events)} failed attempts "
                        f"(lines {ip_events[0].line_number}–{ip_events[-1].line_number}, no timestamps to order them)."
                    ),
                    explanation=(
                        "The log lines carry no usable timestamps, so rate cannot be judged; the sheer "
                        "count of failures from one address is still an indicator for review, not proof of compromise."
                    ),
                    recommendation=(
                        "Check the source logs for timestamps, review whether any attempt succeeded, "
                        "and consider rate-limiting the address."
                    ),
                    rule_id="LOG-BRUTE-002",
                )
            )

    # Isolated failures with no IP grouping and no timestamps at all.
    if undated and not any(f.rule_id in {"LOG-BRUTE-001", "LOG-BRUTE-002"} for f in findings):
        pass  # covered by the per-IP fallback above; nothing extra to add

    return findings


def _find_success_after_failures(events: list[ParsedLine]) -> list[LogFinding]:
    """Success from an IP shortly after failures from the same IP."""
    findings: list[LogFinding] = []
    by_ip: dict[str, list[ParsedLine]] = {}
    for event in events:
        if event.source_ip is None:
            continue
        by_ip.setdefault(event.source_ip, []).append(event)

    for source_ip, ip_events in by_ip.items():
        dated = [e for e in ip_events if e.timestamp is not None]
        if not dated:
            continue
        dated.sort(key=lambda e: e.timestamp)
        pending_failures: list[ParsedLine] = []
        for event in dated:
            if event.outcome == "failed":
                pending_failures.append(event)
                continue
            if event.outcome == "success" and len(pending_failures) >= SUCCESS_AFTER_FAILURES:
                window_seconds = int(
                    (event.timestamp - pending_failures[0].timestamp).total_seconds()
                )
                if window_seconds <= SUCCESS_MAX_WINDOW_SECONDS:
                    usernames = sorted({e.username for e in pending_failures + [event] if e.username})
                    findings.append(
                        LogFinding(
                            title="Login succeeded shortly after repeated failures",
                            category="authentication",
                            severity=Severity.MEDIUM,
                            confidence=Confidence.MEDIUM,
                            line_start=pending_failures[0].line_number,
                            line_end=event.line_number,
                            evidence=(
                                f"{source_ip}: {len(pending_failures)} failed attempts followed by a "
                                f"successful login within {window_seconds} seconds"
                                + (f" for {', '.join(usernames[:3])}" if usernames else "") + "."
                            ),
                            explanation=(
                                "A success that quickly follows failed attempts can be a legitimate user "
                                "who finally remembered the password — or the successful end of a "
                                "password-guessing run. Treat it as a question to answer, not a verdict."
                            ),
                            recommendation=(
                                "Confirm with the account owner that the success was legitimate, check the "
                                "session activity afterwards, and rotate credentials if it cannot be explained."
                            ),
                            rule_id="LOG-SUCCESS-001",
                        )
                    )
            pending_failures = []
    return findings


CREDENTIAL_MATERIAL = re.compile(
    r"(?i)\b(?:authorization\s*:\s*(?:basic|bearer)\b|\bAKIA[0-9A-Z]{16}\b|\bpassword\s*[:=]\s*\S+)"
)


def _find_secret_leaks(raw_lines: list[str], masked_lines: list[str]) -> list[LogFinding]:
    """Flag lines that carry credential material, detected on the RAW text and
    reported with masked evidence only."""
    findings: list[LogFinding] = []
    for number, (raw, masked) in enumerate(zip(raw_lines, masked_lines), start=1):
        if CREDENTIAL_MATERIAL.search(raw):
            findings.append(
                LogFinding(
                    title="Credential material visible in log line",
                    category="secrets",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.LOW,
                    line_start=number,
                    line_end=number,
                    evidence=masked.strip()[:200],
                    explanation=(
                        "Logs that capture credentials are dangerous to keep and to share — anyone "
                        "reading the log inherits the session or key. The value is masked in this output."
                    ),
                    recommendation=(
                        "Trim credential material at the source (web server log format), rotate the "
                        "credential if it was logged, and restrict access to existing logs."
                    ),
                    rule_id="LOG-SECRET-001",
                )
            )
    return findings
