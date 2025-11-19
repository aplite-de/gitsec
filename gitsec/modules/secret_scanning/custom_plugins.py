import re

from detect_secrets.plugins.base import RegexBasedDetector


class DatabaseConnectionStringDetector(RegexBasedDetector):
    """Detects database connection strings with embedded credentials."""

    secret_type = "Database Connection String"

    denylist = (
        # PostgreSQL/MySQL/MongoDB with password
        re.compile(
            r"(?i)(postgresql|postgres|mysql|mongodb|redis)://[^:]+:([^@\s]{3,})@"
        ),
        # MSSQL connection string
        re.compile(r'(?i)Server=.+;Database=.+;User Id=[^;]+;Password=([^;"\'\s]{3,})'),
        # Generic connection string with password
        re.compile(
            r'(?i)connection[_-]?string["\']?\s*[:=]\s*["\']?[^"\']*password=([^;"\']{3,})'
        ),
    )


class GenericAPIKeyDetector(RegexBasedDetector):
    """Detects generic API key patterns with high entropy."""

    secret_type = "Generic API Key"

    denylist = (
        re.compile(
            r'(?i)api[_-]?key["\'`]?\s*[:=]\s*["\'`]([A-Za-z0-9_\-]{32,})["\'`]'
        ),
        re.compile(r'(?i)apikey["\'`]?\s*[:=]\s*["\'`]([A-Za-z0-9_\-]{32,})["\'`]'),
        re.compile(
            r'(?i)api[_-]?secret["\'`]?\s*[:=]\s*["\'`]([A-Za-z0-9_\-]{32,})["\'`]'
        ),
        re.compile(r"(?i)x-api-key:\s*([A-Za-z0-9_\-]{32,})"),
    )


class GoogleCloudAPIKeyDetector(RegexBasedDetector):
    """Detects Google Cloud API keys."""

    secret_type = "Google Cloud API Key"

    denylist = (re.compile(r"AIza[0-9A-Za-z_\-]{35}"),)


class DatadogAPIKeyDetector(RegexBasedDetector):
    """Detects Datadog API and application keys."""

    secret_type = "Datadog Key"

    denylist = (
        re.compile(
            r'(?i)datadog[_-]?api[_-]?key["\'`]?\s*[:=]\s*["\'`]([a-z0-9]{32,})["\'`]'
        ),
        re.compile(
            r'(?i)dd[_-]?api[_-]?key["\'`]?\s*[:=]\s*["\'`]([a-z0-9]{32,})["\'`]'
        ),
    )


class CloudflareAPITokenDetector(RegexBasedDetector):
    """Detects Cloudflare API tokens."""

    secret_type = "Cloudflare API Token"

    denylist = (
        re.compile(
            r'(?i)cloudflare[_-]?api[_-]?token["\'`]?\s*[:=]\s*["\'`]([A-Za-z0-9_\-]{40,})["\'`]'
        ),
    )


class DockerHubAccessTokenDetector(RegexBasedDetector):
    """Detects Docker Hub access tokens."""

    secret_type = "Docker Hub Token"

    denylist = (re.compile(r"dckr_pat_[A-Za-z0-9_\-]{32,}"),)


class AnthropicAPIKeyDetector(RegexBasedDetector):
    """Detects Anthropic (Claude) API keys."""

    secret_type = "Anthropic API Key"

    denylist = (re.compile(r"sk-ant-api03-[A-Za-z0-9\-_]{95}"),)
