"""Check if users have excessive repository access permissions."""

import time
from typing import Iterable

import typer

from gitsec.core.github_api import GitHubClient, format_api_error
from gitsec.models import Finding

ADMIN_WARN_THRESHOLD = 5
ADMIN_FAIL_THRESHOLD = 15
WRITE_WARN_THRESHOLD = 20
WRITE_FAIL_THRESHOLD = 50

CHUNK_SIZE = 25
DELAY_BETWEEN_CHUNKS = 2


def run(client: GitHubClient, org: str, max_repos: int = 100, **_) -> Iterable[Finding]:
    try:
        typer.echo(f"Fetching organization members for {org}...")
        org_members = client.rest_paginate(f"/orgs/{org}/members", per_page=100)

        if not org_members:
            return

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
        owners = []
        try:
            owner_response = client.rest_paginate(
                f"/orgs/{org}/members", params={"role": "admin"}, per_page=100
            )
            owners = [
                member.get("login") for member in owner_response if member.get("login")
            ]
            if owners:
                typer.echo(f"Found {len(owners)} organization owners")
        except Exception:
            typer.echo("Could not retrieve organization owners")

        typer.echo(f"Analyzing permissions for {len(org_members)} members...")
        members_processed = 0

        for member in org_members:
            username = member.get("login")
            if not username:
                continue

            members_processed += 1
            if members_processed % 10 == 0:
                typer.echo(
                    f"Progress: {members_processed}/{len(org_members)} members processed"
                )

            if username in owners:
                yield Finding(
                    check_id="org-user-access",
                    resource=f"org/{org}",
                    evidence=f"User '{username}' has organization owner privileges",
                    notes="Organization owner role grants admin access to all repositories",
                )
                continue

            admin_repos = []
            write_repos = []

            for i, repo in enumerate(repos_to_check):
                repo_name = repo.get("full_name")
                if not repo_name:
                    continue

                try:
                    perm_response = client.get(
                        f"/repos/{repo_name}/collaborators/{username}/permission"
                    )
                    permission = perm_response.get("permission", "none")

                    if permission == "admin":
                        admin_repos.append(repo_name)
                    elif permission in ["maintain", "push"]:
                        write_repos.append(repo_name)

                except Exception:
                    continue

                if (i + 1) % CHUNK_SIZE == 0 and i + 1 < len(repos_to_check):
                    time.sleep(DELAY_BETWEEN_CHUNKS)

            admin_count = len(admin_repos)
            write_count = len(write_repos)
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
            f"Analysis complete: {len(org_members)} members, {len(owners)} owners, {len(repos_to_check)} repositories checked"
        )

    except Exception as e:
        yield Finding(
            check_id="org-user-access",
            resource=f"org/{org}",
            evidence="Error analyzing user access",
            notes=format_api_error(e),
            is_error=True,
        )
