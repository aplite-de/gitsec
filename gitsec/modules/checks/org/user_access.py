"""Check if users have excessive repository access permissions."""

from collections import defaultdict
from typing import Dict, Iterable, List, Set

import typer

from gitsec.core.github_api import GitHubClient, format_api_error
from gitsec.models import Finding

ADMIN_WARN_THRESHOLD = 5
ADMIN_FAIL_THRESHOLD = 15
WRITE_WARN_THRESHOLD = 20
WRITE_FAIL_THRESHOLD = 50


def run(client: GitHubClient, org: str, max_repos: int = 100, **_) -> Iterable[Finding]:
    try:
        typer.echo(f"Fetching organization repositories for {org}...")
        org_repos = client.rest_paginate(f"/orgs/{org}/repos", per_page=100)

        priority_repos = sorted(
            org_repos,
            key=lambda x: (
                x.get("private", False),
                -x.get("stargazers_count", 0),
                x.get("updated_at", ""),
            ),
            reverse=True,
        )

        if max_repos > 0:
            repos_to_check = priority_repos[:max_repos]
            typer.echo(
                f"Analyzing top {len(repos_to_check)} repositories (use max_repos=0 for complete analysis)"
            )
        else:
            repos_to_check = priority_repos
            typer.echo(
                f"Analyzing all {len(repos_to_check)} repositories (may take time due to rate limiting)"
            )

        typer.echo("Identifying organization owners...")
        owners: Set[str] = set()
        try:
            owner_response = client.rest_paginate(
                f"/orgs/{org}/members", params={"role": "admin"}, per_page=100
            )
            owners = {
                member.get("login") for member in owner_response if member.get("login")
            }
            if owners:
                typer.echo(f"Found {len(owners)} organization owners")
        except Exception:
            typer.echo("Could not retrieve organization owners")

        admin_repos: Dict[str, List[str]] = defaultdict(list)
        write_repos: Dict[str, List[str]] = defaultdict(list)

        for i, repo in enumerate(repos_to_check):
            repo_name = repo.get("full_name")
            if not repo_name:
                continue

            if (i + 1) % 10 == 0 or i + 1 == len(repos_to_check):
                typer.echo(
                    f"Progress: {i + 1}/{len(repos_to_check)} repositories scanned"
                )

            try:
                collaborators = client.rest_paginate(
                    f"/repos/{repo_name}/collaborators", per_page=100
                )
            except Exception:
                continue

            for collab in collaborators:
                username = collab.get("login")
                if not username or username in owners:
                    continue

                role = collab.get("role_name", "")
                if role == "admin":
                    admin_repos[username].append(repo_name)
                elif role in ("maintain", "write"):
                    write_repos[username].append(repo_name)

        for username in sorted(owners):
            yield Finding(
                check_id="org-user-access",
                resource=f"org/{org}",
                evidence=f"User '{username}' has organization owner privileges",
                notes="Organization owner role grants admin access to all repositories",
            )

        all_users = sorted(set(admin_repos.keys()) | set(write_repos.keys()))
        for username in all_users:
            admin_count = len(admin_repos[username])
            write_count = len(write_repos[username])
            total_elevated = admin_count + write_count

            if admin_count > ADMIN_FAIL_THRESHOLD:
                yield Finding(
                    check_id="org-user-access",
                    resource=f"org/{org}",
                    evidence=f"User '{username}' has admin access to {admin_count} repositories",
                    notes=f"Exceeds threshold of {ADMIN_FAIL_THRESHOLD} repositories (total elevated: {total_elevated})",
                )
            elif admin_count > ADMIN_WARN_THRESHOLD:
                yield Finding(
                    check_id="org-user-access",
                    resource=f"org/{org}",
                    evidence=f"User '{username}' has admin access to {admin_count} repositories",
                    notes=f"Exceeds warning threshold of {ADMIN_WARN_THRESHOLD} repositories (total elevated: {total_elevated})",
                )
            elif write_count > WRITE_FAIL_THRESHOLD:
                yield Finding(
                    check_id="org-user-access",
                    resource=f"org/{org}",
                    evidence=f"User '{username}' has write access to {write_count} repositories",
                    notes=f"Exceeds threshold of {WRITE_FAIL_THRESHOLD} repositories (admin: {admin_count})",
                )
            elif write_count > WRITE_WARN_THRESHOLD:
                yield Finding(
                    check_id="org-user-access",
                    resource=f"org/{org}",
                    evidence=f"User '{username}' has write access to {write_count} repositories",
                    notes=f"Exceeds warning threshold of {WRITE_WARN_THRESHOLD} repositories (admin: {admin_count})",
                )

        typer.echo(
            f"Analysis complete: {len(all_users)} users with elevated access, {len(owners)} owners, {len(repos_to_check)} repositories checked"
        )

    except Exception as e:
        yield Finding(
            check_id="org-user-access",
            resource=f"org/{org}",
            evidence="Error analyzing user access",
            notes=format_api_error(e),
            is_error=True,
        )
