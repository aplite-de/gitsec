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
    if "/" not in repo:
        raise ValueError("--repo must be in the form 'owner/repo'")
    owner, name = repo.split("/", 1)

    try:
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

        if not branch_name:
            yield Finding(
                check_id="repo-pr-required",
                resource=f"repo/{entity}",
                evidence="Unable to determine branch",
                notes="Repository may not have any branches",
            )
            return

        protection = client.get(f"/repos/{owner}/{name}/branches/{branch_name}/protection")
        pr_required = bool(protection.get("required_pull_request_reviews"))

        if not pr_required:
            yield Finding(
                check_id="repo-pr-required",
                resource=f"repo/{entity}",
                evidence=f"Branch '{branch_name}' does not require pull request reviews",
            )
    except Exception as e:
        yield Finding(
            check_id="repo-pr-required",
            resource=f"repo/{repo}",
            evidence="Error checking PR requirements",
            notes=format_api_error(e),
            is_error=True,
        )
