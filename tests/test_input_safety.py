"""URL normalization and SSRF destination controls (PRD FR-03, FR-04)."""

from __future__ import annotations

import pytest

from app.services.input_safety import (
    SafeInputError,
    normalize_url,
    resolve_redirect,
    validate_url,
)


class TestNormalizeUrl:
    def test_bare_domain_defaults_to_https(self):
        assert normalize_url("example.com") == "https://example.com/"

    def test_scheme_and_host_lowercased_with_path(self):
        assert normalize_url("HTTPS://EXAMPLE.com/a?b=1") == "https://example.com/a?b=1"

    def test_http_scheme_is_allowed(self):
        assert normalize_url("http://example.com") == "http://example.com/"

    def test_empty_and_whitespace_rejected(self):
        for raw in ("", "   ", None):
            with pytest.raises(SafeInputError):
                normalize_url(raw)

    def test_control_characters_rejected(self):
        with pytest.raises(SafeInputError):
            normalize_url("https://example.com/\x00evil")

    def test_non_http_scheme_rejected(self):
        for raw in ("ftp://example.com", "javascript:alert(1)", "file:///etc/passwd"):
            with pytest.raises(SafeInputError):
                normalize_url(raw)

    def test_embedded_credentials_rejected(self):
        with pytest.raises(SafeInputError, match="credentials"):
            normalize_url("https://user:pass@example.com")

    def test_percent_encoded_host_rejected(self):
        with pytest.raises(SafeInputError):
            normalize_url("https://example%2Ecom@evil.com/")

    def test_invalid_port_rejected(self):
        with pytest.raises(SafeInputError, match="port"):
            normalize_url("https://example.com:99999/")

    def test_idn_host_is_normalized(self):
        assert normalize_url("https://ünicode-example.com") == "https://xn--nicode-example-fsb.com/"


class TestValidateUrl:
    @pytest.mark.parametrize(
        "url",
        [
            "http://127.0.0.1/",
            "http://127.0.0.1:8080/admin",
            "http://localhost/",
            "https://[::1]/",
            "https://[::ffff:127.0.0.1]/",
            "http://169.254.169.254/latest/meta-data/",
            "http://10.0.0.1/",
            "http://192.168.1.50/",
            "http://172.16.0.5/",
            "https://2130706433/",  # not parsed as an address; must be refused anyway
        ],
    )
    def test_private_and_ambiguous_targets_are_blocked(self, url):
        with pytest.raises(SafeInputError):
            validate_url(url)

    def test_internal_looking_hostnames_are_blocked(self):
        for host in ("localhost", "myserver.local", "db.internal", "nas.home.arpa"):
            with pytest.raises(SafeInputError):
                validate_url(f"https://{host}/")

    def test_host_resolving_to_private_ip_is_blocked(self):
        def resolver(host):
            return ["10.1.2.3"]

        with pytest.raises(SafeInputError, match="private or reserved"):
            validate_url("https://rebind.example/", resolver=resolver)

    def test_public_host_passes_validation(self):
        def resolver(host):
            assert host == "xn--nicode-example-4db.com" or host == "example.com"
            return ["93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"]

        normalized = validate_url("https://example.com/page", resolver=resolver)
        assert normalized == "https://example.com/page"

    def test_suffix_boundary_172_32_is_public(self):
        def resolver(host):
            return ["172.32.0.1"]

        assert validate_url("https://example.com/", resolver=resolver)

    def test_loopback_boundary_127_0_0_0_is_blocked(self):
        def resolver(host):
            return ["127.0.0.0"]

        with pytest.raises(SafeInputError):
            validate_url("https://example.com/", resolver=resolver)


class TestResolveRedirect:
    def test_relative_location_resolved(self):
        assert (
            resolve_redirect("/login", "https://example.com/start")
            == "https://example.com/login"
        )

    def test_absolute_location_resolved(self):
        assert (
            resolve_redirect("https://other.example/x", "https://example.com/")
            == "https://other.example/x"
        )

    def test_empty_location_rejected(self):
        with pytest.raises(SafeInputError):
            resolve_redirect("", "https://example.com/")

    def test_non_http_scheme_rejected(self):
        with pytest.raises(SafeInputError, match="unsupported scheme"):
            resolve_redirect("ftp://example.com/file", "https://example.com/")


class TestRejectionBranches:
    """Error paths in the SSRF guard itself — each is a security control."""

    def test_custom_resolver_exceptions_propagate_to_route_handler(self):
        """Custom resolvers (tests only) may raise raw errors; the route's
        catch-all converts them. Production always uses default_resolver,
        whose wrapping is asserted separately."""
        import socket

        def resolver(host):
            raise socket.gaierror(-2, "Name or service not known")

        with pytest.raises(socket.gaierror):
            validate_url("https://unresolvable.example/", resolver=resolver)

    def test_default_resolver_wraps_gaierror(self, monkeypatch):
        import socket

        from app.services.input_safety import default_resolver

        def fake_getaddrinfo(*args, **kwargs):
            raise socket.gaierror(-2, "Name or service not known")

        monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
        with pytest.raises(SafeInputError, match="could not be resolved"):
            default_resolver("example.com")

    def test_empty_host_rejected(self):
        with pytest.raises(SafeInputError, match="no host"):
            normalize_url("https://")

    def test_overlong_host_rejected(self):
        with pytest.raises(SafeInputError, match="too long"):
            normalize_url("https://" + "a" * 300 + ".com/")

    def test_space_in_host_rejected(self):
        # The whole-URL whitespace guard fires before the host-character guard.
        with pytest.raises(SafeInputError, match="whitespace or control"):
            normalize_url("https://exa mple.com/")

    def test_backslash_in_host_rejected(self):
        # Backslash makes the netloc parse as a bad port; still rejected.
        with pytest.raises(SafeInputError):
            normalize_url("https:\\\\evil.com")

    def test_idna_failure_rejected(self):
        # A single label over 63 characters fails IDNA encoding.
        with pytest.raises(SafeInputError, match="not a valid domain"):
            normalize_url("https://" + "ü" * 64 + ".com/")

    def test_port_with_garbage_value_rejected(self):
        with pytest.raises(SafeInputError, match="port"):
            normalize_url("https://example.com:notaport/")

    def test_valid_port_survives_normalization(self):
        assert (
            normalize_url("https://example.com:8443/path")
            == "https://example.com:8443/path"
        )

    def test_validate_url_rejects_credentials(self):
        with pytest.raises(SafeInputError, match="credentials"):
            validate_url("https://user:pass@example.com/")

    def test_validate_url_rejects_non_http_scheme(self):
        with pytest.raises(SafeInputError, match="Only http"):
            validate_url("ftp://example.com/")

    def test_malformed_dot_host_rejected(self):
        # "https://./" is caught earlier as an invalid domain name.
        with pytest.raises(SafeInputError):
            validate_url("https://./")

    def test_ipv6_literal_loopback_rejected(self):
        with pytest.raises(SafeInputError, match="private or reserved"):
            validate_url("https://[::1]:8080/")
