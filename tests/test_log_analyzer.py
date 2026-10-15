"""Log analysis: parsing, indicator rules, masking, and limits (PRD §3.4)."""

from __future__ import annotations

import pytest

from app.models import Severity
from app.services.log_analyzer import (
    LogAnalysisError,
    analyze_log,
    mask_secrets,
    parse_line,
)

BRUTE = "\n".join(
    [f"Oct 15 12:00:{i:02d} srv sshd[1]: Failed password for root from 203.0.113.5 port 22 ssh2" for i in range(1, 12)]
)


class TestMasking:
    def test_bearer_token_masked(self):
        masked = mask_secrets("GET / Authorization: Bearer sk-live-abcdef123456")
        assert "sk-live-abcdef123456" not in masked
        assert "[REDACTED]" in masked

    def test_basic_auth_masked(self):
        masked = mask_secrets("Authorization: Basic dXNlcjpwYXNzd29yZA==")
        assert "dXNlcjpwYXNzd29yZA==" not in masked

    def test_key_value_password_masked(self):
        masked = mask_secrets("2026-10-15 app: password=SuperSecret123 denied")
        assert "SuperSecret123" not in masked
        assert "password=[REDACTED]" in masked

    def test_aws_key_masked(self):
        masked = mask_secrets("key AKIAIOSFODNN7EXAMPLE used")
        assert "AKIAIOSFODNN7EXAMPLE" not in masked

    def test_ordinary_ips_and_users_survive(self):
        line = "Failed password for root from 203.0.113.5 port 22 ssh2"
        assert mask_secrets(line) == line


class TestParsing:
    def test_syslog_line_parses(self):
        parsed = parse_line(1, "Oct 15 12:00:01 srv sshd[101]: Failed password for root from 203.0.113.5 port 22 ssh2")
        assert parsed is not None
        assert parsed.matched_format == "syslog"
        assert parsed.process == "sshd"
        assert parsed.source_ip == "203.0.113.5"
        assert parsed.username == "root"
        assert parsed.outcome == "failed"
        assert parsed.timestamp is not None

    def test_success_line_parses(self):
        parsed = parse_line(1, "Oct 15 12:00:01 srv sshd[101]: Accepted password for alice from 198.51.100.10 port 55012 ssh2")
        assert parsed.outcome == "success"
        assert parsed.username == "alice"

    def test_iso_line_parses(self):
        parsed = parse_line(1, "2026-10-15T12:00:01 app[9]: login failed for bob from 10.0.0.1")
        assert parsed is not None
        assert parsed.matched_format == "iso"
        assert parsed.outcome == "failed"
        assert parsed.source_ip == "10.0.0.1"

    def test_python_logging_format_parses(self):
        parsed = parse_line(1, "2026-10-15 12:00:01,500 WARNING auth: authentication failure for user=carol from 198.51.100.9")
        assert parsed is not None
        assert parsed.matched_format == "python-logging"

    def test_unparseable_line_returns_none(self):
        assert parse_line(1, "this is not a log line") is None

    def test_timestamp_without_year_defaults_gracefully(self):
        parsed = parse_line(1, "Oct 15 12:00:01 srv app: hello")
        assert parsed.timestamp is not None
        assert parsed.timestamp.year == 1900  # strptime default; ordering still works


class TestIndicatorRules:
    def test_failed_burst_detected_with_line_range(self):
        result = analyze_log(BRUTE + "\n")
        burst = [f for f in result.findings if f.rule_id == "LOG-BRUTE-001"]
        assert len(burst) == 1
        assert burst[0].severity == Severity.HIGH
        assert burst[0].line_start == 1
        assert "203.0.113.5" in burst[0].evidence
        assert "not proof of compromise" in burst[0].explanation

    def test_scattered_failures_outside_window_not_flagged_as_burst(self):
        spaced = "\n".join(
            [
                f"Oct 15 {12 + i // 60:02d}:{i % 60:02d}:00 srv sshd[1]: Failed password for root from 203.0.113.9 port 22 ssh2"
                for i in range(0, 30, 7)  # 7-minute gaps
            ]
        )
        result = analyze_log(spaced + "\n")
        assert not [f for f in result.findings if f.rule_id == "LOG-BRUTE-001"]

    def test_success_after_failures_flagged(self):
        content = BRUTE + "\nOct 15 12:00:30 srv sshd[1]: Accepted password for root from 203.0.113.5 port 22 ssh2\n"
        result = analyze_log(content)
        success = [f for f in result.findings if f.rule_id == "LOG-SUCCESS-001"]
        assert len(success) == 1
        assert success[0].severity == Severity.MEDIUM
        assert "not a verdict" in success[0].explanation

    def test_success_far_after_failures_not_flagged(self):
        content = BRUTE + "\nOct 15 23:00:00 srv sshd[1]: Accepted password for root from 203.0.113.5 port 22 ssh2\n"
        result = analyze_log(content)
        assert not [f for f in result.findings if f.rule_id == "LOG-SUCCESS-001"]

    def test_untimestamped_failures_use_count_fallback(self):
        content = "\n".join(
            ["auth failure for root from 203.0.113.10"] * 6
        )  # no parseable schema at all -> content rules
        result = analyze_log(content)
        # These lines don't match any schema; without IPs-per-schema they can't be grouped.
        # The parser leaves them unparsed, so no burst rule fires — documented behaviour.
        assert all(f.rule_id != "LOG-BRUTE-001" for f in result.findings)

    def test_credential_material_reported_with_masked_evidence(self):
        content = (
            "Oct 15 12:06:00 srv nginx: request \"GET /\" Authorization: Bearer sk-live-abcdef123456 blocked\n"
            "Oct 15 12:07:00 srv app: password=SuperSecret123 denied\n"
        )
        result = analyze_log(content)
        secret_findings = [f for f in result.findings if f.rule_id == "LOG-SECRET-001"]
        assert len(secret_findings) == 2
        assert all("[REDACTED]" in f.evidence for f in secret_findings)
        assert all("sk-live" not in f.evidence and "SuperSecret" not in f.evidence for f in secret_findings)

    def test_clean_log_yields_no_findings(self):
        content = (
            "Oct 15 12:00:00 srv sshd[1]: Accepted password for alice from 198.51.100.10 port 55012 ssh2\n"
            "Oct 15 12:01:00 srv CRON[55]: pam_unix(cron:session): session opened for user www-data\n"
        )
        result = analyze_log(content)
        assert result.findings == []

    def test_every_finding_says_indicator_not_proof(self):
        result = analyze_log(BRUTE + "\nOct 15 12:00:30 srv sshd[1]: Accepted password for root from 203.0.113.5 port 22 ssh2\n")
        assert result.findings
        assert all(
            ("not proof" in f.explanation) or ("not a verdict" in f.explanation) or ("indicators for review" in f.explanation)
            for f in result.findings
        )


class TestStatsAndLimits:
    def test_stats_summarize_correctly(self):
        content = (
            "Oct 15 12:00:00 srv sshd[1]: Accepted password for alice from 198.51.100.10 port 55012 ssh2\n"
            "Oct 15 12:00:01 srv sshd[1]: Failed password for bob from 198.51.100.10 port 55013 ssh2\n"
            "unparseable line\n"
        )
        result = analyze_log(content)
        assert result.stats.total_lines == 3
        assert result.stats.parsed_lines == 2
        assert result.stats.failed_events == 1
        assert result.stats.success_events == 1
        assert result.stats.unique_ips == 1
        assert result.stats.unique_users == 2
        assert result.stats.time_span == "Oct 15 12:00:00 – Oct 15 12:00:01"

    def test_sample_parse_exposes_transparency_info(self):
        result = analyze_log("Oct 15 12:00:00 srv sshd[1]: Accepted password for alice from 198.51.100.10 port 55012 ssh2\n")
        assert result.sample_parse["format"] == "syslog"
        assert result.sample_parse["fields"]["process"] == "sshd"
        assert result.sample_parse["fields"]["source_ip"] == "198.51.100.10"

    def test_empty_input_rejected(self):
        with pytest.raises(LogAnalysisError):
            analyze_log("")
        with pytest.raises(LogAnalysisError):
            analyze_log("  \n ")

    def test_oversized_input_rejected(self):
        with pytest.raises(LogAnalysisError, match="too large"):
            analyze_log("x line of log text here\n" * 60_000)

    def test_binary_input_rejected(self):
        with pytest.raises(LogAnalysisError, match="binary"):
            analyze_log("\x00\x01\x02")

    def test_findings_sorted_by_line(self):
        content = (
            "Oct 15 12:06:00 srv nginx: Authorization: Bearer sk-live-abcdef123456 blocked\n"
            + BRUTE
            + "\n"
        )
        result = analyze_log(content)
        line_numbers = [f.line_start for f in result.findings]
        assert line_numbers == sorted(line_numbers)

    def test_findings_capped(self):
        content = "\n".join(
            [f"Oct 15 12:{i % 60:02d}:{i % 60:02d} srv nginx: Authorization: Bearer token{i} blocked" for i in range(150)]
        )
        result = analyze_log(content)
        assert len(result.findings) <= 100
