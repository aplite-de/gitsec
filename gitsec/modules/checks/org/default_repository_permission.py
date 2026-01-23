from typing import Iterable

from gitsec.core.github_api import GitHubClient, format_api_error
from gitsec.models import Finding


def run(client: GitHubClient, org: str, **_) -> Iterable[Finding]:
    try:
        data = client.get(f"/orgs/{org}")
        default_permission = data.get("default_repository_permission", None)

        if default_permission in ["read", "write", "admin"]:
            yield Finding(
                check_id="org-default-repo-permission",
                resource=f"org/{org}",
                evidence=f"Organization has overly permissive default repository permission: {default_permission}",
            )
        elif default_permission is None:
            yield Finding(
                check_id="org-default-repo-permission",
                resource=f"org/{org}",
                evidence="Unable to determine default_repository_permission status",
                notes="Field not visible with this token or GHES version may not support this check",
                is_error=True,
            )

    except Exception as e:
        yield Finding(
            check_id="org-default-repo-permission",
            resource=f"org/{org}",
            evidence="Error checking default_repository_permission status",
            notes=format_api_error(e),
            is_error=True,
        )
