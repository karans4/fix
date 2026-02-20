"""Tests for the scrubber module."""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import pytest
from scrubber import scrub


USERNAME = os.environ.get("USER") or os.environ.get("LOGNAME") or "user"
HOME = os.path.expanduser("~")


# --- env_vars ---

class TestEnvVars:
    def test_key_value_redacted(self):
        text = "API_KEY=sk-abc123 rest"
        result, cats = scrub(text)
        assert "sk-abc123" not in result
        assert "API_KEY=[REDACTED]" in result or "API_KEY='[REDACTED]'" in result
        assert "env_vars" in cats

    def test_short_key_not_matched(self):
        text = "AB=xy rest"
        result, cats = scrub(text, config={"categories": ["env_vars"]})
        assert result == text
        assert "env_vars" not in cats

    def test_normal_code_unaffected(self):
        text = "int x = 5;\nreturn 0;"
        result, cats = scrub(text, config={"categories": ["env_vars"]})
        assert result == text
        assert "env_vars" not in cats

    def test_quoted_value(self):
        text = 'SECRET_TOKEN="mytoken123" next'
        result, cats = scrub(text, config={"categories": ["env_vars"]})
        assert "mytoken123" not in result
        assert "env_vars" in cats


# --- tokens ---

class TestTokens:
    def test_sk_proj_redacted(self):
        text = "key is sk-proj-abcdefghijklmnopqrst"
        result, cats = scrub(text, config={"categories": ["tokens"]})
        assert "sk-proj-" not in result
        assert "[REDACTED]" in result
        assert "tokens" in cats

    def test_ghp_redacted(self):
        token = "ghp_" + "a" * 36
        text = f"token: {token}"
        result, cats = scrub(text, config={"categories": ["tokens"]})
        assert token not in result
        assert "tokens" in cats

    def test_bearer_redacted(self):
        text = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.stuff.here"
        result, cats = scrub(text, config={"categories": ["tokens"]})
        assert "eyJ" not in result
        assert "tokens" in cats

    def test_token_param_redacted(self):
        text = "url?token=abcdefghij1234"
        result, cats = scrub(text, config={"categories": ["tokens"]})
        assert "abcdefghij1234" not in result
        assert "tokens" in cats

    def test_password_param_redacted(self):
        text = "password=hunter2"
        result, cats = scrub(text, config={"categories": ["tokens"]})
        assert "hunter2" not in result
        assert "tokens" in cats

    def test_aws_key_redacted(self):
        text = "AKIAIOSFODNN7EXAMPLE"
        result, cats = scrub(text, config={"categories": ["tokens"]})
        assert "AKIAIOSFODNN7EXAMPLE" not in result
        assert "tokens" in cats


# --- paths ---

class TestPaths:
    def test_home_path_scrubbed(self):
        text = f"{HOME}/projects/foo"
        result, cats = scrub(text, config={"categories": ["paths"]})
        assert USERNAME not in result
        assert "/home/[USER]/projects/foo" in result
        assert "paths" in cats

    def test_other_path_untouched(self):
        text = "/usr/local/bin/python"
        result, cats = scrub(text, config={"categories": ["paths"]})
        assert result == text
        assert "paths" not in cats


# --- ips ---

class TestIPs:
    def test_private_192_redacted(self):
        text = "connect to 192.168.1.1 on port 80"
        result, cats = scrub(text, config={"categories": ["ips"]})
        assert "192.168.1.1" not in result
        assert "[REDACTED_IP]" in result
        assert "ips" in cats

    def test_private_10_redacted(self):
        text = "host: 10.0.0.1"
        result, cats = scrub(text, config={"categories": ["ips"]})
        assert "10.0.0.1" not in result
        assert "[REDACTED_IP]" in result
        assert "ips" in cats

    def test_localhost_preserved(self):
        text = "listening on 127.0.0.1:8080"
        result, cats = scrub(text, config={"categories": ["ips"]})
        assert "127.0.0.1" in result

    def test_zero_preserved(self):
        text = "bind 0.0.0.0"
        result, cats = scrub(text, config={"categories": ["ips"]})
        assert "0.0.0.0" in result


# --- emails ---

class TestEmails:
    def test_email_redacted(self):
        text = "contact user@example.com for info"
        result, cats = scrub(text, config={"categories": ["emails"]})
        assert "user@example.com" not in result
        assert "[REDACTED_EMAIL]" in result
        assert "emails" in cats


# --- private keys ---

class TestPrivateKeys:
    def test_rsa_key_redacted(self):
        text = "-----BEGIN RSA PRIVATE KEY-----\nMIIE...lots of base64...\n-----END RSA PRIVATE KEY-----"
        result, cats = scrub(text, config={"categories": ["private_keys"]})
        assert "BEGIN RSA PRIVATE KEY" not in result
        assert "[REDACTED_PRIVATE_KEY]" in result
        assert "private_keys" in cats

    def test_ec_key_redacted(self):
        text = "-----BEGIN EC PRIVATE KEY-----\ndata\n-----END EC PRIVATE KEY-----"
        result, cats = scrub(text, config={"categories": ["private_keys"]})
        assert "BEGIN EC PRIVATE KEY" not in result
        assert "private_keys" in cats

    def test_public_key_not_redacted(self):
        text = "-----BEGIN PUBLIC KEY-----\ndata\n-----END PUBLIC KEY-----"
        result, cats = scrub(text, config={"categories": ["private_keys"]})
        assert "BEGIN PUBLIC KEY" in result


# --- jwts ---

class TestJWTs:
    def test_jwt_redacted(self):
        text = "token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        result, cats = scrub(text, config={"categories": ["jwts"]})
        assert "eyJ" not in result
        assert "[REDACTED_JWT]" in result
        assert "jwts" in cats


# --- connection strings ---

class TestConnStrings:
    def test_postgres_redacted(self):
        text = "DATABASE_URL=postgres://admin:s3cret@db.host.com:5432/mydb"
        result, cats = scrub(text, config={"categories": ["conn_strings"]})
        assert "s3cret" not in result
        assert "[REDACTED_CONNECTION_STRING]" in result
        assert "conn_strings" in cats

    def test_mongodb_redacted(self):
        text = "mongodb+srv://user:pass@cluster.mongodb.net/db"
        result, cats = scrub(text, config={"categories": ["conn_strings"]})
        assert "pass" not in result
        assert "conn_strings" in cats

    def test_redis_redacted(self):
        text = "redis://:mypassword@redis.host:6379/0"
        result, cats = scrub(text, config={"categories": ["conn_strings"]})
        assert "mypassword" not in result
        assert "conn_strings" in cats


# --- git credential URLs ---

class TestGitCreds:
    def test_git_https_cred_redacted(self):
        text = "remote: https://user:ghp_abc123def456ghi789jklmnop@github.com/repo.git"
        result, cats = scrub(text, config={"categories": ["git_creds"]})
        assert "ghp_abc123" not in result
        assert "[REDACTED_URL]" in result
        assert "git_creds" in cats


# --- HTTP auth headers ---

class TestHTTPAuth:
    def test_authorization_header_redacted(self):
        text = "Authorization: Bearer abc123token456"
        result, cats = scrub(text, config={"categories": ["http_auth"]})
        assert "abc123token456" not in result
        assert "http_auth" in cats

    def test_cookie_header_redacted(self):
        text = "Cookie: session=abc123xyz"
        result, cats = scrub(text, config={"categories": ["http_auth"]})
        assert "abc123xyz" not in result
        assert "http_auth" in cats

    def test_x_api_key_redacted(self):
        text = "X-API-Key: mysecretapikey123"
        result, cats = scrub(text, config={"categories": ["http_auth"]})
        assert "mysecretapikey123" not in result
        assert "http_auth" in cats


# --- credit cards ---

class TestCreditCards:
    def test_valid_cc_redacted(self):
        # 4532015112830366 passes Luhn
        text = "card: 4532 0151 1283 0366"
        result, cats = scrub(text, config={"categories": ["credit_cards"]})
        assert "4532" not in result
        assert "[REDACTED_CC]" in result
        assert "credit_cards" in cats

    def test_invalid_cc_not_redacted(self):
        # 1234 5678 9012 3456 fails Luhn
        text = "ref: 1234 5678 9012 3456"
        result, cats = scrub(text, config={"categories": ["credit_cards"]})
        assert "1234 5678 9012 3456" in result


# --- SSN ---

class TestSSN:
    def test_ssn_redacted(self):
        text = "SSN: 123-45-6789"
        result, cats = scrub(text, config={"categories": ["ssn"]})
        assert "123-45-6789" not in result
        assert "[REDACTED_SSN]" in result
        assert "ssn" in cats


# --- phone ---

class TestPhone:
    def test_us_phone_redacted(self):
        text = "call (555) 123-4567"
        result, cats = scrub(text, config={"categories": ["phone"]})
        assert "555" not in result
        assert "[REDACTED_PHONE]" in result
        assert "phone" in cats

    def test_international_phone_redacted(self):
        text = "call +1 555 123 4567"
        result, cats = scrub(text, config={"categories": ["phone"]})
        assert "555" not in result
        assert "phone" in cats


# --- TOTP ---

class TestTOTP:
    def test_totp_uri_redacted(self):
        text = "otpauth://totp/Example:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example"
        result, cats = scrub(text, config={"categories": ["totp"]})
        assert "JBSWY3DPEHPK3PXP" not in result
        assert "[REDACTED_TOTP]" in result
        assert "totp" in cats


# --- hex secrets ---

class TestHexSecrets:
    def test_long_hex_redacted(self):
        text = "key: " + "a1b2c3d4e5f6" * 6  # 72 hex chars, high entropy
        result, cats = scrub(text, config={"categories": ["hex_secrets"]})
        assert "a1b2c3d4e5f6" not in result
        assert "[REDACTED_HEX]" in result
        assert "hex_secrets" in cats

    def test_repeated_hex_not_redacted(self):
        text = "hash: " + "0" * 64  # low entropy
        result, cats = scrub(text, config={"categories": ["hex_secrets"]})
        assert "0" * 64 in result


# --- vendor tokens ---

class TestVendorTokens:
    def test_stripe_secret_key(self):
        text = "STRIPE_KEY=sk_live_abcdefghijklmnopqrstuv"
        result, cats = scrub(text, config={"categories": ["tokens"]})
        assert "sk_live_" not in result
        assert "tokens" in cats

    def test_sendgrid_key(self):
        text = "SG.abcdefghijklmnopqrstuv.abcdefghijklmnopqrstuvwxyz01234567890abcde"
        result, cats = scrub(text, config={"categories": ["tokens"]})
        assert "SG." not in result
        assert "tokens" in cats

    def test_google_api_key(self):
        text = "key=AIzaSyA-abcdefghijklmnopqrstuvwxyz12345"
        result, cats = scrub(text, config={"categories": ["tokens"]})
        assert "AIzaSy" not in result
        assert "tokens" in cats


# --- custom patterns ---

class TestCustomPatterns:
    def test_custom_pattern(self):
        text = "project myproject-42 is live"
        config = {"custom_patterns": [("myproject-\\d+", "[PROJECT_ID]")]}
        result, cats = scrub(text, config=config)
        assert "myproject-42" not in result
        assert "[PROJECT_ID]" in result
        assert "custom" in cats


# --- normal output passthrough ---

class TestPassthrough:
    def test_gcc_error(self):
        text = "main.c:10:5: error: expected ';' before '}' token"
        result, cats = scrub(text, config={"categories": ["env_vars", "tokens"]})
        assert result == text
        assert len(cats) == 0

    def test_gcc_error_with_home_path(self):
        text = f"{HOME}/project/main.c:10:5: error: 'x' undeclared"
        result, cats = scrub(text, config={"categories": ["paths"]})
        assert USERNAME not in result
        assert "/home/[USER]/project/main.c" in result

    def test_python_traceback(self):
        text = (
            'Traceback (most recent call last):\n'
            '  File "test.py", line 1, in <module>\n'
            '    raise ValueError("bad")\n'
            'ValueError: bad'
        )
        result, cats = scrub(text, config={"categories": ["env_vars", "tokens"]})
        assert result == text

    def test_ls_output(self):
        text = "drwxr-xr-x 2 root root 4096 Jan  1 00:00 bin"
        result, cats = scrub(text)
        assert "drwxr-xr-x" in result


# --- edge cases ---

class TestEdgeCases:
    def test_empty_string(self):
        result, cats = scrub("")
        assert result == ""
        assert cats == set()

    def test_none(self):
        result, cats = scrub(None)
        assert result == ""
        assert cats == set()

    def test_no_sensitive_data(self):
        text = "Hello, this is normal text."
        result, cats = scrub(text)
        assert result == text
        assert cats == set()

    def test_multiple_secrets_one_line(self):
        token = "ghp_" + "b" * 36
        text = f"DB_PASSWORD=hunter2 and token {token} here"
        result, cats = scrub(text)
        assert "hunter2" not in result
        assert token not in result

    def test_category_filtering_tokens_only(self):
        text = f"password=secret123 and user@example.com and {HOME}/foo"
        config = {"categories": ["tokens"]}
        result, cats = scrub(text, config=config)
        # tokens scrubbed
        assert "secret123" not in result
        assert "tokens" in cats
        # email and path untouched
        assert "user@example.com" in result
        assert f"{HOME}/foo" in result

    def test_overlapping_env_and_token(self):
        """An env var whose value is itself a token pattern."""
        token = "sk-" + "x" * 25
        text = f"MY_KEY={token} done"
        result, cats = scrub(text)
        assert token not in result
