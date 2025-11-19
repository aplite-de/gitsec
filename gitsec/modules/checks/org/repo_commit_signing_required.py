from typing import Iterable, Optional

from gitsec.core.github_api import GitHubClient
from gitsec.models import Finding

_QUERY = """
query($org: String!, $after: String) {
  organization(login: $org) {
    repositories(first: 100, after: $after, orderBy: {field: NAME, direction: ASC}) {
      pageInfo { hasNextPage endCursor }
      nodes {
        nameWithOwner
        defaultBranchRef {
          name
          branchProtectionRule { requiresCommitSignatures }
        }
      }
    }
  }
}
"""


def run(client: GitHubClient, org: str, **_) -> Iterable[Finding]:
    after: Optional[str] = None

    while True:
        payload = client.graphql(query=_QUERY, variables={"org": org, "after": after})
        repos = (
            (payload.get("data") or {}).get("organization", {}).get("repositories", {})
        )
        for node in repos.get("nodes") or []:
            entity = node.get("nameWithOwner")
            dbr = node.get("defaultBranchRef") or {}
            branch = dbr.get("name")
            rule = dbr.get("branchProtectionRule") or {}
            requires_signatures = rule.get("requiresCommitSignatures")

            if requires_signatures is False:
                yield Finding(
                    check_id="org-commit-signing",
                    resource=f"repo/{entity}",
                    evidence=f"Repository '{entity}' does not require commit signatures on default branch '{branch}'",
                )
            elif requires_signatures is None:
                yield Finding(
                    check_id="org-commit-signing",
                    resource=f"repo/{entity}",
                    evidence=f"Repository '{entity}' cannot determine if commit signing is required",
                    notes="No protection rule on default branch or field not available",
                )

        pi = repos.get("pageInfo") or {}
        if not pi.get("hasNextPage"):
            break
        after = pi.get("endCursor")
