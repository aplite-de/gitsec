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
    if "/" not in repo:
        raise ValueError("--repo must be in the form 'owner/repo'")
    owner, name = repo.split("/", 1)

    try:
        data = client.graphql(query=_QUERY, variables={"owner": owner, "name": name})
        repo_data = (data.get("data") or {}).get("repository") or {}
        entity = repo_data.get("nameWithOwner") or repo
        dbr = repo_data.get("defaultBranchRef") or {}
        branch = dbr.get("name")

        if not branch:
            yield Finding(
                check_id="repo-pr-required",
                resource=f"repo/{entity}",
                evidence="Unable to determine default branch",
                notes="Repository may not have any branches",
            )
            return

        protection = client.get(f"/repos/{owner}/{name}/branches/{branch}/protection")
        pr_required = bool(protection.get("required_pull_request_reviews"))

        if not pr_required:
            yield Finding(
                check_id="repo-pr-required",
                resource=f"repo/{entity}",
                evidence=f"Default branch '{branch}' does not require pull request reviews",
            )
    except Exception as e:
        yield Finding(
            check_id="repo-pr-required",
            resource=f"repo/{repo}",
            evidence="Error checking PR requirements",
            notes=format_api_error(e),
            is_error=True,
        )
