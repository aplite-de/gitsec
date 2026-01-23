from typing import Iterable

from gitsec.core.github_api import GitHubClient, format_api_error
from gitsec.models import Finding


def run(client: GitHubClient, org: str, **_) -> Iterable[Finding]:
    try:
        data = client.get(f"/orgs/{org}")
        members_can_create_repos = data.get("members_can_create_repositories", None)

        if members_can_create_repos is True:
            yield Finding(
                check_id="org-members-can-create-repos",
                resource=f"org/{org}",
                evidence="Organization allows members to create repositories",
            )
        elif members_can_create_repos is None:
            yield Finding(
                check_id="org-members-can-create-repos",
                resource=f"org/{org}",
                evidence="Unable to determine members_can_create_repositories status",
                notes="Field not visible with this token or GHES version may not support this check",
                is_error=True,
            )

    except Exception as e:
        yield Finding(
            check_id="org-members-can-create-repos",
            resource=f"org/{org}",
            evidence="Error checking members_can_create_repositories status",
            notes=format_api_error(e),
            is_error=True,
        )
