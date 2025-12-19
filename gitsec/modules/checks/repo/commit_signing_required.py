from typing import Iterable, Optional

from gitsec.core.github_api import GitHubClient, format_api_error
from gitsec.models import Finding

_DEFAULT_BRANCH_QUERY = """
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

_BRANCH_QUERY = """
query($owner: String!, $name: String!, $branch: String!) {
  repository(owner: $owner, name: $name) {
    nameWithOwner
    ref(qualifiedName: $branch) {
      name
      branchProtectionRule {
        requiresCommitSignatures
      }
    }
  }
}
"""


def run(client: GitHubClient, repo: str, branch: Optional[str] = None, **_) -> Iterable[Finding]:
    owner, name = repo.split("/", 1)

    try:
        if branch:
            query = _BRANCH_QUERY
            variables = {"owner": owner, "name": name, "branch": f"refs/heads/{branch}"}
        else:
            query = _DEFAULT_BRANCH_QUERY
            variables = {"owner": owner, "name": name}
        
        data = client.graphql(query=query, variables=variables)
        repo_data = (data.get("data") or {}).get("repository") or {}
        
        if branch:
            ref = repo_data.get("ref") or {}
            branch_name = branch
            rule = ref.get("branchProtectionRule") or {}
        else:
            dbr = repo_data.get("defaultBranchRef") or {}
            branch_name = dbr.get("name")
            rule = dbr.get("branchProtectionRule") or {}
        
        val = rule.get("requiresCommitSignatures")

        entity = repo_data.get("nameWithOwner") or repo

        if val is True:
            pass
        elif val is False:
            yield Finding(
                check_id="repo-commit-signing",
                resource=f"repo/{entity}",
                evidence=f"Commit signing not required on branch '{branch_name}'",
                notes="Branch protection rule does not enforce commit signatures",
            )
        else:
            yield Finding(
                check_id="repo-commit-signing",
                resource=f"repo/{entity}",
                evidence="Cannot determine if commit signing is required",
                notes=f"No protection rule on branch '{branch_name}' or field not available",
            )
    except Exception as e:
        yield Finding(
            check_id="repo-commit-signing",
            resource=f"repo/{repo}",
            evidence="Error checking commit signing requirement",
            notes=format_api_error(e),
            is_error=True,
        )
