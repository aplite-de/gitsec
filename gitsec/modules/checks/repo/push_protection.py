from typing import Iterable

from gitsec.core.github_api import GitHubClient, format_api_error
from gitsec.models import Finding

_QUERY = """
query($owner: String!, $name: String!) {
  repository(owner: $owner, name: $name) {
    nameWithOwner
    defaultBranchRef { name }
  }
}
"""


def run(client: GitHubClient, repo: str, **_) -> Iterable[Finding]:
    owner, name = repo.split("/", 1)

    data = client.graphql(query=_QUERY, variables={"owner": owner, "name": name})
    repo_data = (data.get("data") or {}).get("repository") or {}
    entity = repo_data.get("nameWithOwner") or repo
    dbr = repo_data.get("defaultBranchRef") or {}
    branch = dbr.get("name")

    try:
        if not branch:
            yield Finding(
                check_id="repo-push-protection",
                resource=f"repo/{entity}",
                evidence="Cannot determine push protection status",
                notes="No default branch information available",
            )
            return

        protection = client.get(f"/repos/{owner}/{name}/branches/{branch}/protection")
        pushes_blocked = protection.get("restrictions") is not None

        if pushes_blocked:
            pass
        else:
            yield Finding(
                check_id="repo-push-protection",
                resource=f"repo/{entity}",
                evidence=f"Direct pushes not blocked on default branch '{branch}'",
                notes="Branch protection does not restrict push access",
            )
    except Exception as e:
        yield Finding(
            check_id="repo-push-protection",
            resource=f"repo/{entity}",
            evidence="Error checking push protection",
            notes=format_api_error(e),
            is_error=True,
        )
