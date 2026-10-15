"""Deterministic source-code security review (PRD §3.3, FR-05, FR-06).

Scope and stance:
- Code submitted through the app is **data**, never executable. Analysis is a
  pure function over text: no evaluation, no parsing that runs embedded code,
  no shell-outs.
- Rules are intentionally starter-grade pattern checks with line references,
  evidence, and a suggested fix. Every finding states it needs human review.
- Results may contain false positives (e.g. `eval` in a sandbox) and false
  negatives (rules cannot understand data flow). The disclaimer accompanies
  every result.

Semgrep note: an optional Semgrep integration was considered and deliberately
deferred — useful Semgrep rule sets are fetched from its registry at runtime,
which conflicts with PHANTOM's local-first, no-external-calls stance. Local
deterministic rules keep the review fully offline.
"""

from __future__ import annotations

import enum
import re
from dataclasses import dataclass

from app.models import Confidence, FindingSource, Severity

MAX_FINDINGS = 100
MAX_CONTENT_CHARS = 524_288  # mirrors UPLOAD_MAX_BYTES; tighter check below

SUPPORTED_LANGUAGES = ("php", "javascript", "python", "sql")

# Uploaded file extensions we accept, mapped to a language.
EXTENSION_LANGUAGES = {
    ".php": "php",
    ".php3": "php",
    ".php4": "php",
    ".php5": "php",
    ".phtml": "php",
    ".inc": "php",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".jsx": "javascript",
    ".py": "python",
    ".pyw": "python",
    ".sql": "sql",
}

LANGUAGE_LABELS = {
    "php": "PHP",
    "javascript": "JavaScript",
    "python": "Python",
    "sql": "SQL",
}


class CodeReviewError(ValueError):
    """User input failed validation; safe to show the reason to the user."""


@dataclass(frozen=True)
class CodeFinding:
    line_start: int
    line_end: int
    title: str
    category: str
    severity: Severity
    confidence: Confidence
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


@dataclass(frozen=True)
class Rule:
    rule_id: str
    language: str  # a SUPPORTED_LANGUAGES entry, or "all"
    pattern: re.Pattern
    title: str
    category: str
    severity: Severity
    explanation: str
    recommendation: str
    confidence: Confidence = Confidence.MEDIUM
    mask_evidence: bool = False  # hide the matched secret value


def _compiled(pattern: str) -> re.Pattern:
    return re.compile(pattern, re.IGNORECASE)


# --- Generic rules (all languages): hardcoded secrets -----------------------
SECRET_ASSIGNMENT = _compiled(
    r"""(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|private[_-]?key|client[_-]?secret)\s*(?::=|=|:)\s*["'][^"']{6,}["']"""
)
AWS_ACCESS_KEY = _compiled(r"\bAKIA[0-9A-Z]{16}\b")
PRIVATE_KEY_BLOCK = _compiled(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
GENERIC_TOKEN = _compiled(
    r"""\b(?:ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk_live_[A-Za-z0-9]{16,}|xox[bap]-[A-Za-z0-9-]{10,})\b"""
)


def _mask_evidence(line: str, match: re.Match) -> str:
    """Keep the rule's key name, mask the secret value in displayed evidence."""
    text = match.group(0)
    if '"' not in text and "'" not in text:
        # Token-style matches (AWS keys, PEM headers, service tokens) carry no
        # separable key name — hide the whole value.
        masked = "[REDACTED]"
    else:
        # Assignment-style matches: reveal the key name, hide the value.
        cut = re.split(r"""["']""", text, maxsplit=1)[0]
        masked = f"{cut}[REDACTED]"
    return line.replace(text, masked)


RULES: list[Rule] = [
    # -- all languages: secrets ------------------------------------------
    Rule(
        rule_id="SEC-SECRET-001",
        language="all",
        pattern=SECRET_ASSIGNMENT,
        title="Possible hardcoded secret",
        category="secrets",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        explanation=(
            "A credential-like value appears to be embedded in source code. Anyone with "
            "access to the code or its history can read it, and rotation is hard."
        ),
        recommendation=(
            "Move secrets to environment variables or a secret manager, and rotate the "
            "exposed value. Remember Git history keeps old copies."
        ),
        mask_evidence=True,
    ),
    Rule(
        rule_id="SEC-SECRET-002",
        language="all",
        pattern=AWS_ACCESS_KEY,
        title="AWS access key in source",
        category="secrets",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        explanation=(
            "A string matching the AWS access-key format was found. Leaked AWS keys are "
            "commonly harvested within minutes of publication."
        ),
        recommendation="Revoke the key in IAM immediately and issue a new one from a secret store.",
        mask_evidence=True,
    ),
    Rule(
        rule_id="SEC-SECRET-003",
        language="all",
        pattern=PRIVATE_KEY_BLOCK,
        title="Private key material in source",
        category="secrets",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        explanation="A PEM private key block was found. Private keys must never be stored in code.",
        recommendation="Remove the key, rotate it, and store it in a key vault or secret manager.",
        mask_evidence=True,
    ),
    Rule(
        rule_id="SEC-SECRET-004",
        language="all",
        pattern=GENERIC_TOKEN,
        title="Possible service token in source",
        category="secrets",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        explanation="A token matching known service-token formats (GitHub, Stripe, Slack) was found.",
        recommendation="Revoke and rotate the token, then load it from the environment instead.",
        mask_evidence=True,
    ),
    # -- PHP ---------------------------------------------------------------
    Rule(
        rule_id="PHP-EVAL-001",
        language="php",
        pattern=_compiled(r"\beval\s*\("),
        title="eval() on dynamic code",
        category="dangerous-function",
        severity=Severity.HIGH,
        explanation=(
            "eval() executes a string as PHP code. If any part of that string can be "
            "influenced by user input, an attacker gains full code execution."
        ),
        recommendation="Refactor to data-driven logic (arrays, match statements) instead of building code strings.",
    ),
    Rule(
        rule_id="PHP-SHELL-001",
        language="php",
        pattern=_compiled(r"\b(?:shell_exec|system|passthru|proc_open|popen)\s*\("),
        title="Shell command execution",
        category="dangerous-function",
        severity=Severity.HIGH,
        explanation=(
            "This function runs a command in the operating-system shell. User input that "
            "reaches it enables command injection."
        ),
        recommendation="Avoid shells entirely where possible; otherwise pass a fixed argument array with escapeshellarg() on every value.",
        confidence=Confidence.MEDIUM,
    ),
    Rule(
        rule_id="PHP-SHELL-002",
        language="php",
        pattern=_compiled(r"`[^`]+`"),
        title="Backtick shell execution",
        category="dangerous-function",
        severity=Severity.HIGH,
        explanation="Backticks execute the enclosed string as a shell command, like shell_exec().",
        recommendation="Replace with a direct function call or a fixed command with escaped arguments.",
        confidence=Confidence.LOW,
    ),
    Rule(
        rule_id="PHP-INCL-001",
        language="php",
        pattern=_compiled(r"\b(?:include|require)(?:_once)?\s*\(?\s*\$"),
        title="Dynamic file inclusion",
        category="injection",
        severity=Severity.HIGH,
        explanation=(
            "Including a file whose path comes from a variable allows path traversal or "
            "remote-file inclusion if the variable is attacker-influenced."
        ),
        recommendation="Map allowed pages to fixed paths with an allow-list; never build include paths from input.",
    ),
    Rule(
        rule_id="PHP-SQLI-001",
        language="php",
        pattern=_compiled(r'''\b(?:mysql_query|mysqli_query|pg_query)\s*\(.*?["'](?:SELECT|INSERT|UPDATE|DELETE)[^"']*["']\s*(?:\.\s*\$|\$|\+)'''),
        title="SQL query built with variables",
        category="injection",
        severity=Severity.HIGH,
        explanation=(
            "A database query is being built by interpolating variables, which is the "
            "classic SQL-injection pattern."
        ),
        recommendation="Use prepared statements with bound parameters (PDO or mysqli with ? placeholders).",
    ),
    Rule(
        rule_id="PHP-XSS-001",
        language="php",
        pattern=_compiled(r"echo\s[^;]*\$_(?:GET|POST|REQUEST|COOKIE)"),
        title="Unescaped output of request input",
        category="xss",
        severity=Severity.MEDIUM,
        explanation=(
            "Request data is echoed directly into the page, allowing reflected "
            "cross-site scripting."
        ),
        recommendation="Escape on output with htmlspecialchars($value, ENT_QUOTES, 'UTF-8'), or use a template engine with autoescaping.",
        confidence=Confidence.MEDIUM,
    ),
    Rule(
        rule_id="PHP-CRYPTO-001",
        language="php",
        pattern=_compiled(r"\b(?:md5|sha1)\s*\(\s*\$"),
        title="Weak hash used (md5/sha1)",
        category="cryptography",
        severity=Severity.MEDIUM,
        explanation="MD5 and SHA1 are fast, unsalted hashes; password guessing is cheap with commodity GPUs.",
        recommendation="Use password_hash() with PASSWORD_DEFAULT (bcrypt/argon2) for passwords.",
        confidence=Confidence.MEDIUM,
    ),
    Rule(
        rule_id="PHP-DESER-001",
        language="php",
        pattern=_compiled(r"\bunserialize\s*\("),
        title="unserialize() on untrusted data",
        category="deserialization",
        severity=Severity.HIGH,
        explanation="unserialize() can instantiate arbitrary objects; crafted payloads lead to code execution (POP chains).",
        recommendation="Exchange data with JSON (json_decode) instead of PHP serialization.",
        confidence=Confidence.MEDIUM,
    ),
    Rule(
        rule_id="PHP-RANDOM-001",
        language="php",
        pattern=_compiled(r"\b(?:rand|mt_rand|uniqid)\s*\("),
        title="Weak randomness used",
        category="cryptography",
        severity=Severity.MEDIUM,
        explanation="rand()/mt_rand()/uniqid() are predictable and must not generate tokens, passwords, or session IDs.",
        recommendation="Use random_bytes() for tokens and random_int() for numbers.",
        confidence=Confidence.LOW,
    ),
    # -- Python --------------------------------------------------------------
    Rule(
        rule_id="PY-EVAL-001",
        language="python",
        pattern=_compiled(r"\b(?:eval|exec)\s*\("),
        title="eval()/exec() on dynamic code",
        category="dangerous-function",
        severity=Severity.HIGH,
        explanation="eval()/exec() run text as Python code; attacker-influenced input means full code execution.",
        recommendation="Replace with data structures or a dedicated parser; if truly needed, restrict with a strict AST allow-list.",
        confidence=Confidence.MEDIUM,
    ),
    Rule(
        rule_id="PY-SHELL-001",
        language="python",
        pattern=_compiled(r"\b(?:os\.system|os\.popen|subprocess\.call|subprocess\.run|subprocess\.Popen)\s*\([^)]*shell\s*=\s*True"),
        title="Shell invocation with shell=True",
        category="dangerous-function",
        severity=Severity.HIGH,
        explanation="shell=True runs the command through a shell, so metacharacters in any input enable injection.",
        recommendation="Pass the command as a list with shell=False (the default) and validate arguments.",
    ),
    Rule(
        rule_id="PY-PICKLE-001",
        language="python",
        pattern=_compiled(r"\bpickle\.loads?\s*\(|\b_yaml?\.load\s*\("),
        title="Deserialization of untrusted data",
        category="deserialization",
        severity=Severity.HIGH,
        explanation="pickle and YAML object deserialization can construct arbitrary objects; untrusted data means code execution.",
        recommendation="Use JSON for untrusted data; for YAML, always specify yaml.safe_load().",
        confidence=Confidence.MEDIUM,
    ),
    Rule(
        rule_id="PY-SQLI-001",
        language="python",
        pattern=_compiled(r"\b(?:execute|executemany)\s*\(\s*f?[\"'][^\"']*(?:SELECT|INSERT|UPDATE|DELETE)[^\"']*%s?[^\"']*[\"']\s*(?:%|\+)"),
        title="SQL query built with string formatting",
        category="injection",
        severity=Severity.HIGH,
        explanation="The query is assembled with %-formatting or concatenation before execution — an SQL-injection pattern.",
        recommendation="Pass parameters separately: cursor.execute('... WHERE id = %s', (value,)).",
        confidence=Confidence.MEDIUM,
    ),
    Rule(
        rule_id="PY-CRYPTO-001",
        language="python",
        pattern=_compiled(r"\b(?:md5|sha1)\s*\("),
        title="Weak hash used (md5/sha1)",
        category="cryptography",
        severity=Severity.MEDIUM,
        explanation="MD5/SHA1 are unsuitable for passwords; they are fast to brute-force.",
        recommendation="Use hashlib.scrypt or the argon2/bcrypt libraries, or passlib's CryptContext.",
        confidence=Confidence.LOW,
    ),
    Rule(
        rule_id="PY-TLS-001",
        language="python",
        pattern=_compiled(r"verify\s*=\s*False"),
        title="TLS certificate verification disabled",
        category="transport",
        severity=Severity.MEDIUM,
        explanation="verify=False in HTTP clients accepts any certificate, enabling man-in-the-middle interception.",
        recommendation="Keep verification on; trust a custom CA bundle instead if needed.",
    ),
    Rule(
        rule_id="PY-DEBUG-001",
        language="python",
        pattern=_compiled(r"debug\s*=\s*True"),
        title="Debug mode enabled in code",
        category="configuration",
        severity=Severity.MEDIUM,
        explanation="Framework debug modes expose source code and interactive consoles (e.g. Werkzeug) in production.",
        recommendation="Drive debug from an environment variable that is off in deployment.",
        confidence=Confidence.LOW,
    ),
    Rule(
        rule_id="PY-RANDOM-001",
        language="python",
        pattern=_compiled(r"\b(?:random\.random|random\.randint)\s*\("),
        title="Weak randomness used",
        category="cryptography",
        severity=Severity.MEDIUM,
        explanation="The random module is not cryptographically secure; its output is predictable.",
        recommendation="Use the secrets module (secrets.token_urlsafe, secrets.randbelow).",
        confidence=Confidence.LOW,
    ),
    # -- JavaScript ------------------------------------------------------------
    Rule(
        rule_id="JS-EVAL-001",
        language="javascript",
        pattern=_compiled(r"\beval\s*\("),
        title="eval() on dynamic code",
        category="dangerous-function",
        severity=Severity.HIGH,
        explanation="eval() executes strings as JavaScript and also disables engine optimizations; input reaching it is code execution.",
        recommendation="Use JSON.parse, lookup objects, or explicit conditionals instead.",
        confidence=Confidence.MEDIUM,
    ),
    Rule(
        rule_id="JS-DOM-001",
        language="javascript",
        pattern=_compiled(r"\.(?:innerHTML|outerHTML)\s*="),
        title="Assignment to innerHTML/outerHTML",
        category="xss",
        severity=Severity.MEDIUM,
        explanation="Setting innerHTML with data that includes user input inserts raw HTML, enabling cross-site scripting.",
        recommendation="Use textContent for text, or build DOM nodes; sanitize with DOMPurify if HTML is required.",
        confidence=Confidence.MEDIUM,
    ),
    Rule(
        rule_id="JS-DOM-002",
        language="javascript",
        pattern=_compiled(r"\bdocument\.write\s*\("),
        title="document.write() used",
        category="xss",
        severity=Severity.MEDIUM,
        explanation="document.write injects raw markup into the document and is a common XSS vector with untrusted data.",
        recommendation="Create elements with createElement/textContent instead.",
        confidence=Confidence.MEDIUM,
    ),
    Rule(
        rule_id="JS-TIMER-001",
        language="javascript",
        pattern=_compiled(r"\b(?:setTimeout|setInterval)\s*\(\s*[\"']"),
        title="Timer scheduled with a string",
        category="dangerous-function",
        severity=Severity.MEDIUM,
        explanation="setTimeout('string') compiles the string like eval().",
        recommendation="Pass a function reference: setTimeout(fn, delay).",
    ),
    Rule(
        rule_id="JS-TLS-001",
        language="javascript",
        pattern=_compiled(r"rejectUnauthorized\s*:\s*false"),
        title="TLS certificate verification disabled",
        category="transport",
        severity=Severity.MEDIUM,
        explanation="rejectUnauthorized:false accepts any certificate, enabling man-in-the-middle attacks.",
        recommendation="Remove the option and configure a proper CA bundle.",
    ),
    Rule(
        rule_id="JS-CRYPTO-001",
        language="javascript",
        pattern=_compiled(r"\bMath\.random\s*\("),
        title="Math.random() used for security values",
        category="cryptography",
        severity=Severity.MEDIUM,
        explanation="Math.random() is not cryptographically secure; tokens from it are predictable.",
        recommendation="Use crypto.getRandomValues() (browser) or crypto.randomUUID()/randomBytes (Node).",
        confidence=Confidence.LOW,
    ),
    # -- SQL -----------------------------------------------------------------
    Rule(
        rule_id="SQL-UNBOUNDED-001",
        language="sql",
        pattern=_compiled(r"^\s*DELETE\s+FROM\s+\S+?(?:\s*;.*)?$"),
        title="DELETE without a WHERE clause",
        category="destructive-operation",
        severity=Severity.MEDIUM,
        explanation="A DELETE statement without WHERE removes every row in the table.",
        recommendation="Add a WHERE clause, or guard bulk deletes behind an explicit confirmation step.",
        confidence=Confidence.LOW,
    ),
    Rule(
        rule_id="SQL-UNBOUNDED-002",
        language="sql",
        pattern=_compiled(r"^\s*UPDATE\s+\S+\s+SET\s+.*(?:\s*;.*)?$"),
        title="UPDATE without a WHERE clause",
        category="destructive-operation",
        severity=Severity.MEDIUM,
        explanation="An UPDATE statement without WHERE rewrites every row in the table.",
        recommendation="Add a WHERE clause, or verify the bulk change is intended inside a transaction.",
        confidence=Confidence.LOW,
    ),
    Rule(
        rule_id="SQL-GRANT-001",
        language="sql",
        pattern=_compiled(r"\bGRANT\s+ALL\b"),
        title="GRANT ALL privileges",
        category="configuration",
        severity=Severity.MEDIUM,
        explanation="Granting all privileges widens the blast radius of both bugs and stolen credentials.",
        recommendation="Grant the narrowest set of privileges per role and database.",
        confidence=Confidence.MEDIUM,
    ),
    Rule(
        rule_id="SQL-SECRET-001",
        language="sql",
        pattern=_compiled(r"--.*(?:password|passwd|secret|api[_-]?key)\s*[:=]\s*\S+"),
        title="Possible secret in a comment",
        category="secrets",
        severity=Severity.HIGH,
        explanation="A comment appears to contain a credential value.",
        recommendation="Remove the secret from the file and rotate it.",
        mask_evidence=True,
        confidence=Confidence.MEDIUM,
    ),
]

RULES_BY_LANGUAGE: dict[str, list[Rule]] = {}
for _rule in RULES:
    RULES_BY_LANGUAGE.setdefault(_rule.language, []).append(_rule)


def detect_language(content: str) -> str | None:
    """Best-effort language guess for pasted content; None if undetectable."""
    head = content[:4000]
    checks: tuple[tuple[str, re.Pattern], ...] = (
        ("php", re.compile(r"<\?php|<\?=|\$\w+\s*=\s*.*;\s*$", re.MULTILINE | re.IGNORECASE)),
        ("python", re.compile(r"^\s*(?:def |class |import \w+$|from \w+ import)", re.MULTILINE)),
        ("javascript", re.compile(r"\b(?:function\s+\w+\s*\(|const \w+|let \w+|var \w+|=>|document\.)")),
        ("sql", re.compile(r"\b(?:SELECT|INSERT\s+INTO|UPDATE|CREATE\s+TABLE|DELETE\s+FROM)\b", re.IGNORECASE)),
    )
    for language, pattern in checks:
        if pattern.search(head):
            return language
    return None


def _validate_content(content: str) -> None:
    if content is None:
        raise CodeReviewError("Paste or upload some code to review.")
    if not content.strip():
        raise CodeReviewError("Paste or upload some code to review.")
    if len(content) > MAX_CONTENT_CHARS:
        raise CodeReviewError("The submission is too large. Split it up or remove unrelated sections.")
    if "\x00" in content:
        raise CodeReviewError("The file looks binary. PHANTOM reviews text source files only.")


def _language_for(language_choice: str, content: str) -> str:
    choice = (language_choice or "").strip().lower()
    if choice in SUPPORTED_LANGUAGES:
        return choice
    if choice in {"", "auto"}:
        detected = detect_language(content)
        if detected is None:
            raise CodeReviewError(
                "Could not detect the language. Pick PHP, JavaScript, Python, or SQL explicitly."
            )
        return detected
    raise CodeReviewError("Unsupported language. Choose PHP, JavaScript, Python, or SQL.")


def analyze_code(content: str, language_choice: str = "auto") -> tuple[str, list[CodeFinding]]:
    """Analyze source text. Pure function over data — the code is never executed.

    Returns (language, findings ordered by line). Raises CodeReviewError for
    invalid or unsupported submissions.
    """
    _validate_content(content)
    language = _language_for(language_choice, content)

    rules = RULES_BY_LANGUAGE.get(language, []) + RULES_BY_LANGUAGE.get("all", [])
    lines = content.splitlines()
    findings: list[CodeFinding] = []
    seen: set[tuple[str, int]] = set()

    for line_number, line in enumerate(lines, start=1):
        for rule in rules:
            if (rule.rule_id, line_number) in seen:
                continue
            match = rule.pattern.search(line)
            if match is None:
                continue
            seen.add((rule.rule_id, line_number))

            evidence = (
                _mask_evidence(line.strip(), match)
                if rule.mask_evidence
                else line.strip()[:200]
            )
            findings.append(
                CodeFinding(
                    line_start=line_number,
                    line_end=line_number,
                    title=rule.title,
                    category=rule.category,
                    severity=rule.severity,
                    confidence=rule.confidence,
                    evidence=evidence,
                    explanation=rule.explanation,
                    recommendation=rule.recommendation,
                    rule_id=rule.rule_id,
                )
            )
            if len(findings) >= MAX_FINDINGS:
                findings.sort(key=lambda f: f.line_start)
                return language, findings

    findings.sort(key=lambda f: f.line_start)
    return language, findings
