"""Deterministic code analysis rules, limits, and safety (PRD §3.3)."""

from __future__ import annotations

import pytest

from app.models import FindingSource, Severity
from app.services.code_analyzer import (
    MAX_FINDINGS,
    CodeReviewError,
    analyze_code,
    detect_language,
)


class TestDetection:
    def test_php_detected(self):
        assert detect_language("<?php\necho 'hi';") == "php"

    def test_python_detected(self):
        assert detect_language("import os\ndef main():\n    pass") == "python"

    def test_javascript_detected(self):
        assert detect_language("const x = 1;\nfunction f() {}") == "javascript"

    def test_sql_detected(self):
        assert detect_language("SELECT * FROM users;") == "sql"

    def test_undetectable_returns_none(self):
        assert detect_language("???") is None


class TestPhpRules:
    def test_eval_flagged_with_line_number(self):
        content = "<?php\n$ok = 1;\neval($_POST['cmd']);\n"
        language, findings = analyze_code(content, "php")
        assert language == "php"
        eval_finding = next(f for f in findings if f.rule_id == "PHP-EVAL-001")
        assert eval_finding.line_start == 3
        assert "eval" in eval_finding.evidence

    def test_shell_functions_flagged(self):
        _, findings = analyze_code("<?php\nsystem('ls ' . $_GET['d']);\nshell_exec($cmd);\n", "php")
        rule_ids = {f.rule_id for f in findings}
        assert {"PHP-SHELL-001"} <= rule_ids

    def test_backticks_flagged(self):
        _, findings = analyze_code("<?php\n$out = `ls -la`;\n", "php")
        assert any(f.rule_id == "PHP-SHELL-002" for f in findings)

    def test_sqli_pattern_flagged(self):
        content = "<?php\n$result = mysqli_query($conn, \"SELECT * FROM u WHERE id = \" . $_GET['id']);\n"
        _, findings = analyze_code(content, "php")
        assert any(f.rule_id == "PHP-SQLI-001" for f in findings)
        assert all(f.severity == Severity.HIGH for f in findings if f.rule_id == "PHP-SQLI-001")

    def test_unserialize_and_weak_hash_flagged(self):
        content = "<?php\n$data = unserialize($input);\n$h = md5($password);\n"
        _, findings = analyze_code(content, "php")
        rule_ids = {f.rule_id for f in findings}
        assert {"PHP-DESER-001", "PHP-CRYPTO-001"} <= rule_ids

    def test_clean_php_has_no_findings(self):
        content = "<?php\n$name = htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');\necho $name;\n"
        _, findings = analyze_code(content, "php")
        assert findings == []


class TestPythonRules:
    def test_eval_and_shell_true_flagged(self):
        content = (
            "import os, subprocess\n"
            "value = eval(user_input)\n"
            "subprocess.run(cmd, shell=True)\n"
        )
        _, findings = analyze_code(content, "python")
        rule_ids = {f.rule_id for f in findings}
        assert {"PY-EVAL-001", "PY-SHELL-001"} <= rule_ids

    def test_pickle_and_yaml_load_flagged(self):
        content = "import pickle, yaml\ndata = pickle.loads(blob)\nconf = yaml.load(f)\n"
        _, findings = analyze_code(content, "python")
        rule_ids = {f.rule_id for f in findings}
        assert "PY-PICKLE-001" in rule_ids

    def test_verify_false_flagged(self):
        content = "import requests\nr = requests.get(url, verify=False)\n"
        _, findings = analyze_code(content, "python")
        assert any(f.rule_id == "PY-TLS-001" for f in findings)

    def test_debug_true_flagged(self):
        content = "app.run(debug=True)\n"
        _, findings = analyze_code(content, "python")
        assert any(f.rule_id == "PY-DEBUG-001" for f in findings)

    def test_safe_python_is_clean(self):
        content = (
            "import subprocess\n"
            "result = subprocess.run(['ls', path], capture_output=True)\n"
            "import secrets\n"
            "token = secrets.token_urlsafe(32)\n"
        )
        _, findings = analyze_code(content, "python")
        assert findings == []


class TestJavaScriptRules:
    def test_innerhtml_and_eval_flagged(self):
        content = "el.innerHTML = userData;\nconst value = eval(expr);\n"
        _, findings = analyze_code(content, "javascript")
        rule_ids = {f.rule_id for f in findings}
        assert {"JS-DOM-001", "JS-EVAL-001"} <= rule_ids

    def test_string_timer_flagged(self):
        _, findings = analyze_code("setTimeout(\"doThing()\", 100);\n", "javascript")
        assert any(f.rule_id == "JS-TIMER-001" for f in findings)

    def test_reject_unauthorized_false_flagged(self):
        _, findings = analyze_code("https.get(url, { rejectUnauthorized: false });\n", "javascript")
        assert any(f.rule_id == "JS-TLS-001" for f in findings)


class TestSqlRules:
    def test_delete_without_where_flagged(self):
        _, findings = analyze_code("DELETE FROM users;\n", "sql")
        assert any(f.rule_id == "SQL-UNBOUNDED-001" for f in findings)

    def test_delete_with_where_not_flagged(self):
        _, findings = analyze_code("DELETE FROM users WHERE id = 5;\n", "sql")
        assert not any(f.rule_id == "SQL-UNBOUNDED-001" for f in findings)

    def test_grant_all_flagged(self):
        _, findings = analyze_code("GRANT ALL PRIVILEGES ON *.* TO 'app'@'%';\n", "sql")
        assert any(f.rule_id == "SQL-GRANT-001" for f in findings)


class TestSecretRules:
    def test_hardcoded_password_masked_in_evidence(self):
        content = "DB_PASSWORD = 'SuperSecret123'\n"
        _, findings = analyze_code(content, "python")
        secret = next(f for f in findings if f.rule_id == "SEC-SECRET-001")
        assert "SuperSecret123" not in secret.evidence
        assert "[REDACTED]" in secret.evidence
        assert "DB_PASSWORD" in secret.evidence  # the key name stays visible

    def test_aws_key_masked(self):
        content = "aws_key = AKIAIOSFODNN7EXAMPLE\n"  # docs.example AWS sample key
        _, findings = analyze_code(content, "python")
        key_finding = next(f for f in findings if f.rule_id == "SEC-SECRET-002")
        assert "AKIAIOSFODNN7EXAMPLE" not in key_finding.evidence
        assert key_finding.severity == Severity.CRITICAL

    def test_private_key_block_masked(self):
        content = "key = '-----BEGIN RSA PRIVATE KEY-----\\nabc\\n'\n"
        _, findings = analyze_code(content, "python")
        assert any(f.rule_id == "SEC-SECRET-003" for f in findings)

    def test_masked_secret_never_appears_in_any_finding(self):
        content = "password = 'hunter2secret'\n"
        language, findings = analyze_code(content, "python")
        assert all("hunter2secret" not in f.evidence for f in findings)


class TestLimitsAndSafety:
    def test_empty_content_rejected(self):
        with pytest.raises(CodeReviewError):
            analyze_code("", "python")
        with pytest.raises(CodeReviewError):
            analyze_code("   \n  ", "python")

    def test_oversized_content_rejected(self):
        with pytest.raises(CodeReviewError, match="too large"):
            analyze_code("x = 1\n" * 200_000, "python")

    def test_binary_content_rejected(self):
        with pytest.raises(CodeReviewError, match="binary"):
            analyze_code("PK\x00\x03\x04binary", "python")

    def test_unknown_language_rejected(self):
        with pytest.raises(CodeReviewError, match="Unsupported language"):
            analyze_code("code", "ruby")

    def test_undetectable_auto_rejected_with_guidance(self):
        with pytest.raises(CodeReviewError, match="Could not detect"):
            analyze_code("??? ???", "auto")

    def test_findings_capped(self):
        content = "eval(1)\n" * (MAX_FINDINGS + 50)
        _, findings = analyze_code(content, "python")
        assert len(findings) == MAX_FINDINGS

    def test_findings_sorted_by_line(self):
        content = "eval(a)\n\nos.system(b, shell=True)\n"
        _, findings = analyze_code(content, "python")
        line_numbers = [f.line_start for f in findings]
        assert line_numbers == sorted(line_numbers)

    def test_all_findings_are_deterministic_source(self):
        _, findings = analyze_code("<?php\neval(1);\n", "php")
        assert all(f.source_type == FindingSource.RULE for f in findings)

    def test_analysis_is_idempotent(self):
        content = "<?php\neval($_GET['x']);\n"
        first = analyze_code(content, "php")
        second = analyze_code(content, "php")
        assert first == second
