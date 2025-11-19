from __future__ import annotations

import os
import shutil
import tempfile
from typing import Iterable, Optional
from urllib.parse import urlparse

import git
import typer
from detect_secrets.core.secrets_collection import SecretsCollection
from detect_secrets.settings import transient_settings

from gitsec.core.github_api import GitHubClient
from gitsec.models.finding import SecretFinding
from gitsec.modules.secret_scanning import custom_plugins


def is_github_url(path_or_url: str) -> bool:
    try:
        parsed = urlparse(path_or_url)
        if parsed.scheme not in ("http", "https"):
            return False
        host = parsed.netloc.lower()
        if host != "github.com":
            return False
        segments = [seg for seg in parsed.path.split("/") if seg]
        return len(segments) >= 2
    except Exception:
        return False


def clone_repository(repo_url: str, temp_dir: str, token: Optional[str] = None) -> None:
    env = os.environ.copy()
    
    if token:
        env['GIT_TERMINAL_PROMPT'] = '0'
        if repo_url.startswith("https://"):
            clone_url = repo_url.replace("https://", f"https://{token}@")
        else:
            clone_url = repo_url
    else:
        clone_url = repo_url

    git.Repo.clone_from(clone_url, temp_dir, env=env)


def scan_file_for_secrets(file_path: str) -> list:
    try:
        custom_plugins_path = f"file://{os.path.abspath(custom_plugins.__file__)}"

        plugins_config = [
            {"name": "ArtifactoryDetector"},
            {"name": "AWSKeyDetector"},
            {"name": "AzureStorageKeyDetector"},
            {"name": "BasicAuthDetector"},
            {"name": "CloudantDetector"},
            {"name": "DiscordBotTokenDetector"},
            {"name": "GitHubTokenDetector"},
            {"name": "GitLabTokenDetector"},
            # Disabled: too many false positives
            # {"name": "Base64HighEntropyString"},
            # {"name": "HexHighEntropyString"},
            {"name": "IbmCloudIamDetector"},
            {"name": "IbmCosHmacDetector"},
            # Disabled: IPv4 addresses are not secrets
            # {"name": "IPPublicDetector"},
            {"name": "JwtTokenDetector"},
            # Disabled: too many false positives
            # {"name": "KeywordDetector"},
            {"name": "MailchimpDetector"},
            {"name": "NpmDetector"},
            {"name": "OpenAIDetector"},
            {"name": "PrivateKeyDetector"},
            {"name": "PypiTokenDetector"},
            {"name": "SendGridDetector"},
            {"name": "SlackDetector"},
            {"name": "SoftlayerDetector"},
            {"name": "SquareOAuthDetector"},
            {"name": "StripeDetector"},
            {"name": "TelegramBotTokenDetector"},
            {"name": "TwilioKeyDetector"},
            {"name": "DatabaseConnectionStringDetector", "path": custom_plugins_path},
            {"name": "GenericAPIKeyDetector", "path": custom_plugins_path},
            {"name": "GoogleCloudAPIKeyDetector", "path": custom_plugins_path},
            {"name": "DatadogAPIKeyDetector", "path": custom_plugins_path},
            {"name": "CloudflareAPITokenDetector", "path": custom_plugins_path},
            {"name": "DockerHubAccessTokenDetector", "path": custom_plugins_path},
            {"name": "AnthropicAPIKeyDetector", "path": custom_plugins_path},
        ]

        secrets = SecretsCollection()
        with transient_settings({"plugins_used": plugins_config, "filters_used": []}):
            secrets.scan_file(file_path)

        secrets_json = secrets.json()
        found_secrets = []
        for secrets_list in secrets_json.values():
            found_secrets.extend(secrets_list)

        return found_secrets
    except Exception:
        return []


def scan_directory(
    directory_path: str, repository: str = "local"
) -> Iterable[SecretFinding]:
    for root, dirs, files in os.walk(directory_path):
        if ".git" in dirs:
            dirs.remove(".git")

        for filename in files:
            file_path = os.path.join(root, filename)

            try:
                secrets = scan_file_for_secrets(file_path)
                if secrets:
                    for secret in secrets:
                        relative_path = os.path.relpath(file_path, directory_path)
                        secret_type = secret.get("type", "unknown")
                        line_number = secret.get("line_number", None)
                        secret_hash = secret.get("hashed_secret", None)

                        yield SecretFinding(
                            repository=repository,
                            file_path=relative_path,
                            secret_type=secret_type,
                            line_number=line_number,
                            secret_hash=secret_hash,
                        )
            except Exception:
                continue


def scan_local_repository(repo_path: str) -> Iterable[SecretFinding]:
    if not os.path.exists(repo_path):
        typer.echo(
            f"Error: Local repository path does not exist: {repo_path}", err=True
        )
        return

    yield from scan_directory(repo_path, repository=repo_path)


def scan_remote_repository(repo: str, client: GitHubClient) -> Iterable[SecretFinding]:
    if "/" not in repo:
        typer.echo("Error: --repo must be in the form 'owner/repo'", err=True)
        return

    owner, name = repo.split("/", 1)
    repo_url = f"https://github.com/{owner}/{name}.git"
    temp_dir = None

    try:
        temp_dir = tempfile.mkdtemp(prefix="gitsec_scan_")

        clone_repository(
            repo_url,
            temp_dir,
            client.client.headers.get("Authorization", "").replace("Bearer ", ""),
        )

        yield from scan_directory(temp_dir, repository=repo)

    except Exception:
        pass
    finally:
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)


def scan_organization_repositories(
    org: str, client: GitHubClient
) -> Iterable[SecretFinding]:
    try:
        repos = client.rest_paginate(f"/orgs/{org}/repos", per_page=100)

        if not repos:
            return

        for repo in repos:
            repo_name = repo.get("full_name")
            if repo_name:
                yield from scan_remote_repository(repo_name, client)

    except Exception:
        pass
