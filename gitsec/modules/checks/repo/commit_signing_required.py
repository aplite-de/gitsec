from typing import Iterable

from gitsec.core.github_api import GitHubClient, format_api_error
from gitsec.models import Finding

_QUERY = """
query($owner: String!, $name: String!) {
  repository(owner: $owner, name: $name) {
    nameWithOwner
    defaultBranchRef {
      name
      branchProtectionRule {
        requiresCommitSignatures
      }
    }
  }
}
"""


def run(client: GitHubClient, repo: str, **_) -> Iterable[Finding]:
    owner, name = repo.split("/", 1)

    try:
        data = client.graphql(query=_QUERY, variables={"owner": owner, "name": name})
        repo_data = (data.get("data") or {}).get("repository") or {}
        dbr = repo_data.get("defaultBranchRef") or {}
        branch = dbr.get("name")
        rule = dbr.get("branchProtectionRule") or {}
        val = rule.get("requiresCommitSignatures")

        entity = repo_data.get("nameWithOwner") or repo

        if val is True:
            pass
        elif val is False:
            yield Finding(
                check_id="repo-commit-signing",
                resource=f"repo/{entity}",
                evidence=f"Commit signing not required on default branch '{branch}'",
                notes="Branch protection rule does not enforce commit signatures",
            )
        else:
            yield Finding(
                check_id="repo-commit-signing",
                resource=f"repo/{entity}",
                evidence="Cannot determine if commit signing is required",
                notes="No protection rule on default branch or field not available",
            )
    except Exception as e:
        yield Finding(
            check_id="repo-commit-signing",
            resource=f"repo/{repo}",
            evidence="Error checking commit signing requirement",
            notes=format_api_error(e),
            is_error=True,
        )
