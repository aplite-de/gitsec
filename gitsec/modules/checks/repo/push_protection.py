from typing import Iterable, Optional

from gitsec.core.github_api import GitHubClient, format_api_error
from gitsec.models import Finding

_DEFAULT_BRANCH_QUERY = """
query($owner: String!, $name: String!) {
  repository(owner: $owner, name: $name) {
    nameWithOwner
    defaultBranchRef { name }
  }
}
"""

_BRANCH_QUERY = """
query($owner: String!, $name: String!) {
  repository(owner: $owner, name: $name) {
    nameWithOwner
  }
}
"""


def run(client: GitHubClient, repo: str, branch: Optional[str] = None, **_) -> Iterable[Finding]:
    owner, name = repo.split("/", 1)

    if branch:
        query = _BRANCH_QUERY
        branch_name = branch
    else:
        query = _DEFAULT_BRANCH_QUERY
    
    data = client.graphql(query=query, variables={"owner": owner, "name": name})
    repo_data = (data.get("data") or {}).get("repository") or {}
    entity = repo_data.get("nameWithOwner") or repo
    
    if not branch:
        dbr = repo_data.get("defaultBranchRef") or {}
        branch_name = dbr.get("name")

    try:
        if not branch_name:
            yield Finding(
                check_id="repo-push-protection",
                resource=f"repo/{entity}",
                evidence="Cannot determine push protection status",
                notes="No branch information available",
            )
            return

        protection = client.get(f"/repos/{owner}/{name}/branches/{branch_name}/protection")
        pushes_blocked = protection.get("restrictions") is not None

        if pushes_blocked:
            pass
        else:
            yield Finding(
                check_id="repo-push-protection",
                resource=f"repo/{entity}",
                evidence=f"Direct pushes not blocked on branch '{branch_name}'",
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
