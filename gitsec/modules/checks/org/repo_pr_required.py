from typing import Iterable, Optional

from gitsec.core.github_api import GitHubClient, format_api_error
from gitsec.models import Finding

_QUERY = """
query($org: String!, $after: String) {
  organization(login: $org) {
    repositories(first: 100, after: $after, orderBy: {field: NAME, direction: ASC}) {
      pageInfo { hasNextPage endCursor }
      nodes {
        nameWithOwner
        defaultBranchRef { name }
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

            owner, name = (
                entity.split("/", 1) if entity and "/" in entity else (None, None)
            )

            try:
                if not (owner and name and branch):
                    yield Finding(
                        check_id="org-pr-required",
                        resource=f"repo/{entity or 'unknown'}",
                        evidence="Unable to determine default branch",
                        notes="Repository may not have any branches",
                    )
                    continue

                protection = client.get(
                    f"/repos/{owner}/{name}/branches/{branch}/protection"
                )
                pr_required = bool(protection.get("required_pull_request_reviews"))

                if not pr_required:
                    yield Finding(
                        check_id="org-pr-required",
                        resource=f"repo/{entity}",
                        evidence=f"Repository '{entity}' does not require pull request reviews on default branch '{branch}'",
                    )
            except Exception as e:
                yield Finding(
                    check_id="org-pr-required",
                    resource=f"repo/{entity or 'unknown'}",
                    evidence="Error checking PR requirements",
                    notes=format_api_error(e),
                )

        pi = repos.get("pageInfo") or {}
        if not pi.get("hasNextPage"):
            break
        after = pi.get("endCursor")
